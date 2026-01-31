package main

import (
    "context"
    "crypto/tls"
    "encoding/binary"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"

    "github.com/quic-go/quic-go"
)

type DFPHandler struct {
    crypto     *ProtocolCrypto
    compressor *ProtocolCompressor
    basePath   string
    mu         sync.RWMutex
    sessions   map[[16]byte]*SessionKey
    stats      *ServerStats
    version    uint8
    vdisks     map[string]*VirtualDisk
    vdiskMu    sync.RWMutex
}

type ServerStats struct {
    Uploads      uint64
    Downloads    uint64
    Errors       uint64
    BytesSent    uint64
    BytesRecv    uint64
    StartTime    time.Time
    Connections  uint64
    VDiskReads   uint64
    VDiskWrites  uint64
    VDiskBytesRd uint64
    VDiskBytesWr uint64
}

type VirtualDisk struct {
    Name      string
    Path      string
    Size      int64
    BlockSize int32
    Used      int64
    Created   time.Time
    Modified  time.Time
    Flags     uint32
    Version   uint8
    Handle    *os.File
    OpenCount int
    mu        sync.RWMutex
}

type DFPServer struct {
    port    uint16
    tls     *tls.Config
    handler *DFPHandler
}

func NewDFPHandler(password, basePath string) (*DFPHandler, error) {
    crypto := NewProtocolCrypto(password, nil)
    compressor := NewProtocolCompressor()

    os.MkdirAll(basePath, 0700)
    os.MkdirAll(filepath.Join(basePath, "vdisks"), 0700)

    handler := &DFPHandler{
        crypto:     crypto,
        compressor: compressor,
        basePath:   basePath,
        sessions:   make(map[[16]byte]*SessionKey),
        stats: &ServerStats{
            StartTime: time.Now(),
        },
        version: PROTOCOL_VERSION,
        vdisks:  make(map[string]*VirtualDisk),
    }

    handler.loadVirtualDisks()

    return handler, nil
}

func (h *DFPHandler) loadVirtualDisks() {
    vdiskPath := filepath.Join(h.basePath, "vdisks")
    entries, err := os.ReadDir(vdiskPath)
    if err != nil {
        return
    }

    for _, entry := range entries {
        if strings.HasSuffix(entry.Name(), ".meta") {
            metaPath := filepath.Join(vdiskPath, entry.Name())
            metaEncrypted, err := os.ReadFile(metaPath)
            if err != nil {
                continue
            }

            metaBytes, err := h.crypto.DecryptData(metaEncrypted)
            if err != nil {
                continue
            }

            metadata, err := DiskMetadataFromBytes(metaBytes)
            if err != nil {
                continue
            }

            diskPath := filepath.Join(vdiskPath, strings.TrimSuffix(entry.Name(), ".meta")+".vdisk")

            vdisk := &VirtualDisk{
                Name:      metadata.Name,
                Path:      diskPath,
                Size:      metadata.Size,
                BlockSize: metadata.BlockSize,
                Used:      metadata.Used,
                Created:   metadata.Created,
                Modified:  metadata.Modified,
                Flags:     metadata.Flags,
                Version:   metadata.Version,
                OpenCount: 0,
            }

            h.vdiskMu.Lock()
            h.vdisks[metadata.Name] = vdisk
            h.vdiskMu.Unlock()
        }
    }
}

func (h *DFPHandler) saveVirtualDiskMetadata(vdisk *VirtualDisk) error {
    metadata := DiskMetadata{
        Name:      vdisk.Name,
        Size:      vdisk.Size,
        BlockSize: vdisk.BlockSize,
        Created:   vdisk.Created,
        Modified:  vdisk.Modified,
        Flags:     vdisk.Flags,
        Used:      vdisk.Used,
        Version:   h.version,
    }

    metaBytes := metadata.ToBytes()
    metaEncrypted, err := h.crypto.EncryptData(metaBytes)
    if err != nil {
        return err
    }

    metaPath := filepath.Join(h.basePath, "vdisks", vdisk.Name+".meta")
    return os.WriteFile(metaPath, metaEncrypted, 0600)
}

func NewDFPServer(port uint16, handler *DFPHandler) *DFPServer {
    tls, _ := GenerateTLSConfig()

    return &DFPServer{
        port:    port,
        tls:     tls,
        handler: handler,
    }
}

func (s *DFPServer) Run() error {
    addr := fmt.Sprintf("0.0.0.0:%d", s.port)
    listener, err := quic.ListenAddr(addr, s.tls, s.handler.GetQUICConfig())
    if err != nil {
        return err
    }
    defer listener.Close()

    for {
        conn, err := listener.Accept(context.Background())
        if err != nil {
            continue
        }

        go s.handler.HandleConnection(conn)
    }
}

func (h *DFPHandler) GetQUICConfig() *quic.Config {
    return NewProtocolConfig().ToQUICConfig()
}

func (h *DFPHandler) NegotiateVersion(clientVersion uint8) uint8 {
    negotiator := &VersionNegotiator{
        ClientVersion: clientVersion,
        ServerVersion: h.version,
    }

    if !negotiator.Negotiate() {
        return MIN_VERSION
    }

    return negotiator.Negotiated
}

func (h *DFPHandler) ValidateHeader(header ProtocolHeader) error {
    if header.Magic != HEADER_MAGIC {
        return NewProtocolError(ERR_PROTOCOL, "invalid magic")
    }

    if header.Version < MIN_VERSION || header.Version > MAX_VERSION {
        return NewProtocolError(ERR_VERSION, "unsupported version")
    }

    if header.DataLength > MAX_FILE_SIZE {
        return NewProtocolError(ERR_SIZE, "file too large")
    }

    return nil
}

func (h *DFPHandler) HandleConnection(conn quic.Connection) {
    h.mu.Lock()
    h.stats.Connections++
    h.mu.Unlock()

    defer func() {
        if r := recover(); r != nil {
            h.mu.Lock()
            h.stats.Errors++
            h.mu.Unlock()
        }
        conn.CloseWithError(0, "")
    }()

    for {
        stream, err := conn.AcceptStream(context.Background())
        if err != nil {
            break
        }

        go h.HandleStream(stream)
    }
}

func (h *DFPHandler) HandleStream(stream quic.Stream) {
    defer stream.Close()

    var header ProtocolHeader
    if err := binary.Read(stream, binary.BigEndian, &header); err != nil {
        h.SendError(stream, ERR_PROTOCOL, "invalid header")
        return
    }

    if err := h.ValidateHeader(header); err != nil {
        if pe, ok := err.(ProtocolError); ok {
            h.SendError(stream, pe.Code, pe.Message)
        }
        return
    }

    negotiatedVersion := h.NegotiateVersion(header.Version)
    if negotiatedVersion != header.Version {
        h.SendError(stream, ERR_VERSION, fmt.Sprintf("version mismatch: server=%d", negotiatedVersion))
        return
    }

    switch header.Command {
    case CMD_UPLOAD:
        h.HandleUpload(header, stream)
    case CMD_DOWNLOAD:
        h.HandleDownload(header, stream)
    case CMD_LIST:
        h.HandleList(header, stream)
    case CMD_DELETE:
        h.HandleDelete(header, stream)
    case CMD_META:
        h.HandleMeta(header, stream)
    case CMD_PING:
        h.HandlePing(header, stream)
    case CMD_DISK_CREATE:
        h.HandleDiskCreate(header, stream)
    case CMD_DISK_DELETE:
        h.HandleDiskDelete(header, stream)
    case CMD_DISK_LIST:
        h.HandleDiskList(header, stream)
    case CMD_DISK_OPEN:
        h.HandleDiskOpen(header, stream)
    case CMD_DISK_CLOSE:
        h.HandleDiskClose(header, stream)
    case CMD_DISK_READ:
        h.HandleDiskRead(header, stream)
    case CMD_DISK_WRITE:
        h.HandleDiskWrite(header, stream)
    case CMD_DISK_STAT:
        h.HandleDiskStat(header, stream)
    default:
        h.SendError(stream, ERR_UNSUPPORTED, "unknown command")
    }
}

func (h *DFPHandler) HandleUpload(header ProtocolHeader, stream quic.Stream) error {
    h.mu.Lock()
    h.stats.Uploads++
    h.mu.Unlock()

    var nameLen uint32
    if err := binary.Read(stream, binary.BigEndian, &nameLen); err != nil {
        return h.SendError(stream, ERR_PROTOCOL, "invalid name length")
    }

    if nameLen > 4096 {
        return h.SendError(stream, ERR_SIZE, "filename too long")
    }

    nameBytes := make([]byte, nameLen)
    if _, err := io.ReadFull(stream, nameBytes); err != nil {
        return h.SendError(stream, ERR_IO, "failed to read filename")
    }

    fileName := string(nameBytes)
    if !h.validateFileName(fileName) {
        return h.SendError(stream, ERR_PROTOCOL, "invalid filename")
    }

    buffer := make([]byte, CHUNK_SIZE)
    var received uint64
    var data []byte

    for received < header.DataLength {
        toRead := CHUNK_SIZE
        remaining := header.DataLength - received
        if remaining < uint64(toRead) {
            toRead = int(remaining)
        }

        n, err := stream.Read(buffer[:toRead])
        if err != nil && err != io.EOF {
            return h.SendError(stream, ERR_IO, "read error")
        }

        data = append(data, buffer[:n]...)
        received += uint64(n)

        if err == io.EOF {
            break
        }
    }

    if received != header.DataLength {
        return h.SendError(stream, ERR_SIZE, "size mismatch")
    }

    checksum := h.crypto.CalculateChecksum(data)

    var processed []byte
    if header.Flags&FLAG_COMPRESSED != 0 && len(data) > COMPRESS_THRESHOLD {
        processed = h.compressor.Compress(data)
    } else {
        processed = data
    }

    encrypted, err := h.crypto.EncryptData(processed)
    if err != nil {
        return h.SendError(stream, ERR_IO, "encryption failed")
    }

    metadata := FileMetadata{
        Name:      fileName,
        Size:      int64(len(data)),
        Modified:  time.Now(),
        Checksum:  checksum,
        Encrypted: true,
        Compressed: header.Flags&FLAG_COMPRESSED != 0,
        Version:   header.Version,
    }

    metaBytes := metadata.ToBytes()
    metaEncrypted, err := h.crypto.EncryptData(metaBytes)
    if err != nil {
        return h.SendError(stream, ERR_IO, "metadata encryption failed")
    }

    filePath := filepath.Join(h.basePath, fileName+FILE_EXT)
    metaPath := filepath.Join(h.basePath, fileName+".meta")

    if err := os.WriteFile(filePath, encrypted, 0600); err != nil {
        return h.SendError(stream, ERR_IO, "write failed")
    }

    if err := os.WriteFile(metaPath, metaEncrypted, 0600); err != nil {
        os.Remove(filePath)
        return h.SendError(stream, ERR_IO, "metadata write failed")
    }

    h.mu.Lock()
    h.stats.BytesRecv += uint64(len(data))
    h.mu.Unlock()

    response := make([]byte, 1)
    response[0] = ERR_NONE
    stream.Write(response)

    return nil
}

func (h *DFPHandler) HandleDownload(header ProtocolHeader, stream quic.Stream) error {
    h.mu.Lock()
    h.stats.Downloads++
    h.mu.Unlock()

    var nameLen uint32
    if err := binary.Read(stream, binary.BigEndian, &nameLen); err != nil {
        return h.SendError(stream, ERR_PROTOCOL, "invalid name length")
    }

    nameBytes := make([]byte, nameLen)
    if _, err := io.ReadFull(stream, nameBytes); err != nil {
        return h.SendError(stream, ERR_IO, "failed to read filename")
    }

    fileName := string(nameBytes)
    filePath := filepath.Join(h.basePath, fileName+FILE_EXT)
    metaPath := filepath.Join(h.basePath, fileName+".meta")

    metaEncrypted, err := os.ReadFile(metaPath)
    if err != nil {
        return h.SendError(stream, ERR_NOT_FOUND, "file not found")
    }

    metaBytes, err := h.crypto.DecryptData(metaEncrypted)
    if err != nil {
        return h.SendError(stream, ERR_AUTH, "metadata decryption failed")
    }

    metadata, err := FileMetadataFromBytes(metaBytes)
    if err != nil {
        return h.SendError(stream, ERR_PROTOCOL, "invalid metadata")
    }

    encrypted, err := os.ReadFile(filePath)
    if err != nil {
        return h.SendError(stream, ERR_IO, "read error")
    }

    processed, err := h.crypto.DecryptData(encrypted)
    if err != nil {
        return h.SendError(stream, ERR_AUTH, "decryption failed")
    }

    var data []byte
    if metadata.Compressed {
        data, err = h.compressor.Decompress(processed)
        if err != nil {
            return h.SendError(stream, ERR_IO, "decompression failed")
        }
    } else {
        data = processed
    }

    checksum := h.crypto.CalculateChecksum(data)
    if checksum != metadata.Checksum {
        return h.SendError(stream, ERR_CRC, "checksum mismatch")
    }

    responseHeader := ProtocolHeader{
        Magic:      HEADER_MAGIC,
        Version:    header.Version,
        Command:    CMD_DOWNLOAD,
        Flags:      0,
        Sequence:   header.Sequence,
        DataLength: uint64(len(data)),
    }

    if err := binary.Write(stream, binary.BigEndian, responseHeader); err != nil {
        return h.SendError(stream, ERR_IO, "header write failed")
    }

    sent := uint64(0)
    for sent < uint64(len(data)) {
        end := sent + CHUNK_SIZE
        if end > uint64(len(data)) {
            end = uint64(len(data))
        }

        n, err := stream.Write(data[sent:end])
        if err != nil {
            return h.SendError(stream, ERR_IO, "write error")
        }

        sent += uint64(n)
    }

    h.mu.Lock()
    h.stats.BytesSent += sent
    h.mu.Unlock()

    return nil
}

func (h *DFPHandler) HandleList(header ProtocolHeader, stream quic.Stream) error {
    entries, err := os.ReadDir(h.basePath)
    if err != nil {
        return h.SendError(stream, ERR_IO, "read error")
    }

    var files []FileMetadata
    for _, entry := range entries {
        entryName := entry.Name()

        if !strings.HasSuffix(entryName, ".meta") {
            continue
        }

        metaPath := filepath.Join(h.basePath, entryName)

        metaEncrypted, err := os.ReadFile(metaPath)
        if err != nil {
            continue
        }

        metaBytes, err := h.crypto.DecryptData(metaEncrypted)
        if err != nil {
            continue
        }

        metadata, err := FileMetadataFromBytes(metaBytes)
        if err != nil {
            continue
        }

        files = append(files, *metadata)
    }

    count := uint32(len(files))
    if err := binary.Write(stream, binary.BigEndian, count); err != nil {
        return h.SendError(stream, ERR_IO, "write error")
    }

    for _, file := range files {
        metaBytes := file.ToBytes()
        metaEncrypted, err := h.crypto.EncryptData(metaBytes)
        if err != nil {
            continue
        }

        encLen := uint32(len(metaEncrypted))
        if err := binary.Write(stream, binary.BigEndian, encLen); err != nil {
            return h.SendError(stream, ERR_IO, "write error")
        }

        if _, err := stream.Write(metaEncrypted); err != nil {
            return h.SendError(stream, ERR_IO, "write error")
        }
    }

    return nil
}

func (h *DFPHandler) HandleDelete(header ProtocolHeader, stream quic.Stream) error {
    if header.Version < 2 {
        return h.SendError(stream, ERR_UNSUPPORTED, "command requires v2+")
    }

    var nameLen uint32
    if err := binary.Read(stream, binary.BigEndian, &nameLen); err != nil {
        return h.SendError(stream, ERR_PROTOCOL, "invalid name length")
    }

    nameBytes := make([]byte, nameLen)
    if _, err := io.ReadFull(stream, nameBytes); err != nil {
        return h.SendError(stream, ERR_IO, "failed to read filename")
    }

    fileName := string(nameBytes)
    filePath := filepath.Join(h.basePath, fileName+FILE_EXT)
    metaPath := filepath.Join(h.basePath, fileName+".meta")

    if err := os.Remove(filePath); err != nil {
        return h.SendError(stream, ERR_IO, "delete failed")
    }

    os.Remove(metaPath)

    response := make([]byte, 1)
    response[0] = ERR_NONE
    stream.Write(response)

    return nil
}

func (h *DFPHandler) HandleMeta(header ProtocolHeader, stream quic.Stream) error {
    if header.Version < 2 {
        return h.SendError(stream, ERR_UNSUPPORTED, "command requires v2+")
    }

    var nameLen uint32
    if err := binary.Read(stream, binary.BigEndian, &nameLen); err != nil {
        return h.SendError(stream, ERR_PROTOCOL, "invalid name length")
    }

    nameBytes := make([]byte, nameLen)
    if _, err := io.ReadFull(stream, nameBytes); err != nil {
        return h.SendError(stream, ERR_IO, "failed to read filename")
    }

    fileName := string(nameBytes)
    metaPath := filepath.Join(h.basePath, fileName+".meta")

    metaEncrypted, err := os.ReadFile(metaPath)
    if err != nil {
        return h.SendError(stream, ERR_NOT_FOUND, "file not found")
    }

    encLen := uint32(len(metaEncrypted))
    if err := binary.Write(stream, binary.BigEndian, encLen); err != nil {
        return h.SendError(stream, ERR_IO, "write error")
    }

    if _, err := stream.Write(metaEncrypted); err != nil {
        return h.SendError(stream, ERR_IO, "write error")
    }

    return nil
}

func (h *DFPHandler) HandlePing(header ProtocolHeader, stream quic.Stream) error {
    response := ProtocolHeader{
        Magic:      HEADER_MAGIC,
        Version:    header.Version,
        Command:    CMD_PING,
        Flags:      0,
        Sequence:   header.Sequence,
        DataLength: 0,
    }

    if err := binary.Write(stream, binary.BigEndian, response); err != nil {
        return h.SendError(stream, ERR_IO, "write error")
    }

    return nil
}

func (h *DFPHandler) HandleDiskCreate(header ProtocolHeader, stream quic.Stream) error {
    if header.Version < 3 {
        return h.SendError(stream, ERR_UNSUPPORTED, "command requires v3+")
    }

    var nameLen uint32
    if err := binary.Read(stream, binary.BigEndian, &nameLen); err != nil {
        return h.SendError(stream, ERR_PROTOCOL, "invalid name length")
    }

    nameBytes := make([]byte, nameLen)
    if _, err := io.ReadFull(stream, nameBytes); err != nil {
        return h.SendError(stream, ERR_IO, "failed to read disk name")
    }

    diskName := string(nameBytes)
    if !h.validateFileName(diskName) {
        return h.SendError(stream, ERR_PROTOCOL, "invalid disk name")
    }

    var size, blockSize uint32
    if err := binary.Read(stream, binary.BigEndian, &size); err != nil {
        return h.SendError(stream, ERR_PROTOCOL, "invalid size")
    }
    if err := binary.Read(stream, binary.BigEndian, &blockSize); err != nil {
        return h.SendError(stream, ERR_PROTOCOL, "invalid block size")
    }

    if blockSize == 0 || blockSize > 65536 {
        return h.SendError(stream, ERR_SIZE, "invalid block size")
    }

    h.vdiskMu.Lock()
    defer h.vdiskMu.Unlock()

    if _, exists := h.vdisks[diskName]; exists {
        return h.SendError(stream, ERR_VDISK_INVAL, "disk already exists")
    }

    diskPath := filepath.Join(h.basePath, "vdisks", diskName+".vdisk")
    file, err := os.Create(diskPath)
    if err != nil {
        return h.SendError(stream, ERR_IO, "failed to create disk file")
    }
    defer file.Close()

    if err := file.Truncate(int64(size) * int64(blockSize)); err != nil {
        os.Remove(diskPath)
        return h.SendError(stream, ERR_IO, "failed to allocate disk space")
    }

    vdisk := &VirtualDisk{
        Name:      diskName,
        Path:      diskPath,
        Size:      int64(size) * int64(blockSize),
        BlockSize: int32(blockSize),
        Used:      0,
        Created:   time.Now(),
        Modified:  time.Now(),
        Flags:     0,
        Version:   h.version,
        Handle:    nil,
        OpenCount: 0,
    }

    h.vdisks[diskName] = vdisk

    if err := h.saveVirtualDiskMetadata(vdisk); err != nil {
        delete(h.vdisks, diskName)
        os.Remove(diskPath)
        return h.SendError(stream, ERR_IO, "failed to save metadata")
    }

    response := make([]byte, 1)
    response[0] = ERR_NONE
    stream.Write(response)

    return nil
}

func (h *DFPHandler) HandleDiskDelete(header ProtocolHeader, stream quic.Stream) error {
    if header.Version < 3 {
        return h.SendError(stream, ERR_UNSUPPORTED, "command requires v3+")
    }

    var nameLen uint32
    if err := binary.Read(stream, binary.BigEndian, &nameLen); err != nil {
        return h.SendError(stream, ERR_PROTOCOL, "invalid name length")
    }

    nameBytes := make([]byte, nameLen)
    if _, err := io.ReadFull(stream, nameBytes); err != nil {
        return h.SendError(stream, ERR_IO, "failed to read disk name")
    }

    diskName := string(nameBytes)

    h.vdiskMu.Lock()
    defer h.vdiskMu.Unlock()

    vdisk, exists := h.vdisks[diskName]
    if !exists {
        return h.SendError(stream, ERR_NOT_FOUND, "disk not found")
    }

    if vdisk.OpenCount > 0 {
        return h.SendError(stream, ERR_VDISK_BUSY, "disk is open")
    }

    diskPath := filepath.Join(h.basePath, "vdisks", diskName+".vdisk")
    metaPath := filepath.Join(h.basePath, "vdisks", diskName+".meta")

    delete(h.vdisks, diskName)
    os.Remove(diskPath)
    os.Remove(metaPath)

    response := make([]byte, 1)
    response[0] = ERR_NONE
    stream.Write(response)

    return nil
}

func (h *DFPHandler) HandleDiskList(header ProtocolHeader, stream quic.Stream) error {
    if header.Version < 3 {
        return h.SendError(stream, ERR_UNSUPPORTED, "command requires v3+")
    }

    h.vdiskMu.RLock()
    defer h.vdiskMu.RUnlock()

    count := uint32(len(h.vdisks))
    if err := binary.Write(stream, binary.BigEndian, count); err != nil {
        return h.SendError(stream, ERR_IO, "write error")
    }

    for _, vdisk := range h.vdisks {
        metadata := DiskMetadata{
            Name:      vdisk.Name,
            Size:      vdisk.Size,
            BlockSize: vdisk.BlockSize,
            Created:   vdisk.Created,
            Modified:  vdisk.Modified,
            Flags:     vdisk.Flags,
            Used:      vdisk.Used,
            Version:   vdisk.Version,
        }

        metaBytes := metadata.ToBytes()
        metaEncrypted, err := h.crypto.EncryptData(metaBytes)
        if err != nil {
            continue
        }

        encLen := uint32(len(metaEncrypted))
        if err := binary.Write(stream, binary.BigEndian, encLen); err != nil {
            return h.SendError(stream, ERR_IO, "write error")
        }

        if _, err := stream.Write(metaEncrypted); err != nil {
            return h.SendError(stream, ERR_IO, "write error")
        }
    }

    return nil
}

func (h *DFPHandler) HandleDiskOpen(header ProtocolHeader, stream quic.Stream) error {
    if header.Version < 3 {
        return h.SendError(stream, ERR_UNSUPPORTED, "command requires v3+")
    }

    var nameLen uint32
    if err := binary.Read(stream, binary.BigEndian, &nameLen); err != nil {
        return h.SendError(stream, ERR_PROTOCOL, "invalid name length")
    }

    nameBytes := make([]byte, nameLen)
    if _, err := io.ReadFull(stream, nameBytes); err != nil {
        return h.SendError(stream, ERR_IO, "failed to read disk name")
    }

    diskName := string(nameBytes)

    h.vdiskMu.Lock()
    defer h.vdiskMu.Unlock()

    vdisk, exists := h.vdisks[diskName]
    if !exists {
        return h.SendError(stream, ERR_NOT_FOUND, "disk not found")
    }

    if vdisk.Handle == nil {
        file, err := os.OpenFile(vdisk.Path, os.O_RDWR, 0600)
        if err != nil {
            return h.SendError(stream, ERR_IO, "failed to open disk")
        }
        vdisk.Handle = file
    }

    vdisk.OpenCount++

    response := make([]byte, 1)
    response[0] = ERR_NONE
    stream.Write(response)

    return nil
}

func (h *DFPHandler) HandleDiskClose(header ProtocolHeader, stream quic.Stream) error {
    if header.Version < 3 {
        return h.SendError(stream, ERR_UNSUPPORTED, "command requires v3+")
    }

    var nameLen uint32
    if err := binary.Read(stream, binary.BigEndian, &nameLen); err != nil {
        return h.SendError(stream, ERR_PROTOCOL, "invalid name length")
    }

    nameBytes := make([]byte, nameLen)
    if _, err := io.ReadFull(stream, nameBytes); err != nil {
        return h.SendError(stream, ERR_IO, "failed to read disk name")
    }

    diskName := string(nameBytes)

    h.vdiskMu.Lock()
    defer h.vdiskMu.Unlock()

    vdisk, exists := h.vdisks[diskName]
    if !exists {
        return h.SendError(stream, ERR_NOT_FOUND, "disk not found")
    }

    if vdisk.OpenCount > 0 {
        vdisk.OpenCount--
        if vdisk.OpenCount == 0 && vdisk.Handle != nil {
            vdisk.Handle.Close()
            vdisk.Handle = nil
        }
    }

    response := make([]byte, 1)
    response[0] = ERR_NONE
    stream.Write(response)

    return nil
}

func (h *DFPHandler) HandleDiskRead(header ProtocolHeader, stream quic.Stream) error {
    if header.Version < 3 {
        return h.SendError(stream, ERR_UNSUPPORTED, "command requires v3+")
    }

    var nameLen uint32
    if err := binary.Read(stream, binary.BigEndian, &nameLen); err != nil {
        return h.SendError(stream, ERR_PROTOCOL, "invalid name length")
    }

    nameBytes := make([]byte, nameLen)
    if _, err := io.ReadFull(stream, nameBytes); err != nil {
        return h.SendError(stream, ERR_IO, "failed to read disk name")
    }

    diskName := string(nameBytes)

    var offset, length uint64
    if err := binary.Read(stream, binary.BigEndian, &offset); err != nil {
        return h.SendError(stream, ERR_PROTOCOL, "invalid offset")
    }
    if err := binary.Read(stream, binary.BigEndian, &length); err != nil {
        return h.SendError(stream, ERR_PROTOCOL, "invalid length")
    }

    if length > uint64(header.DataLength) {
        length = uint64(header.DataLength)
    }
    if length == 0 || length > MAX_FILE_SIZE {
        return h.SendError(stream, ERR_SIZE, "invalid read length")
    }

    h.vdiskMu.RLock()
    vdisk, exists := h.vdisks[diskName]
    h.vdiskMu.RUnlock()

    if !exists {
        return h.SendError(stream, ERR_NOT_FOUND, "disk not found")
    }

    if vdisk.Handle == nil {
        return h.SendError(stream, ERR_VDISK_BUSY, "disk not open")
    }

    vdisk.mu.RLock()
    defer vdisk.mu.RUnlock()

    if offset+length > uint64(vdisk.Size) {
        return h.SendError(stream, ERR_SIZE, "read beyond disk size")
    }

    buffer := make([]byte, length)
    n, err := vdisk.Handle.ReadAt(buffer, int64(offset))
    if err != nil && err != io.EOF {
        return h.SendError(stream, ERR_IO, "read failed")
    }

    responseHeader := ProtocolHeader{
        Magic:      HEADER_MAGIC,
        Version:    header.Version,
        Command:    CMD_DISK_READ,
        Flags:      0,
        Sequence:   header.Sequence,
        DataLength: uint64(n),
    }

    if err := binary.Write(stream, binary.BigEndian, responseHeader); err != nil {
        return h.SendError(stream, ERR_IO, "header write failed")
    }

    if _, err := stream.Write(buffer[:n]); err != nil {
        return h.SendError(stream, ERR_IO, "data write failed")
    }

    h.mu.Lock()
    h.stats.VDiskReads++
    h.stats.VDiskBytesRd += uint64(n)
    h.mu.Unlock()

    return nil
}

func (h *DFPHandler) HandleDiskWrite(header ProtocolHeader, stream quic.Stream) error {
    if header.Version < 3 {
        return h.SendError(stream, ERR_UNSUPPORTED, "command requires v3+")
    }

    var nameLen uint32
    if err := binary.Read(stream, binary.BigEndian, &nameLen); err != nil {
        return h.SendError(stream, ERR_PROTOCOL, "invalid name length")
    }

    nameBytes := make([]byte, nameLen)
    if _, err := io.ReadFull(stream, nameBytes); err != nil {
        return h.SendError(stream, ERR_IO, "failed to read disk name")
    }

    diskName := string(nameBytes)

    var offset uint64
    if err := binary.Read(stream, binary.BigEndian, &offset); err != nil {
        return h.SendError(stream, ERR_PROTOCOL, "invalid offset")
    }

    h.vdiskMu.RLock()
    vdisk, exists := h.vdisks[diskName]
    h.vdiskMu.RUnlock()

    if !exists {
        return h.SendError(stream, ERR_NOT_FOUND, "disk not found")
    }

    if vdisk.Handle == nil {
        return h.SendError(stream, ERR_VDISK_BUSY, "disk not open")
    }

    vdisk.mu.Lock()
    defer vdisk.mu.Unlock()

    if offset+uint64(header.DataLength) > uint64(vdisk.Size) {
        return h.SendError(stream, ERR_VDISK_FULL, "write beyond disk size")
    }

    buffer := make([]byte, CHUNK_SIZE)
    var received uint64
    var data []byte

    for received < header.DataLength {
        toRead := CHUNK_SIZE
        remaining := header.DataLength - received
        if remaining < uint64(toRead) {
            toRead = int(remaining)
        }

        n, err := stream.Read(buffer[:toRead])
        if err != nil && err != io.EOF {
            return h.SendError(stream, ERR_IO, "read error")
        }

        data = append(data, buffer[:n]...)
        received += uint64(n)

        if err == io.EOF {
            break
        }
    }

    if received != header.DataLength {
        return h.SendError(stream, ERR_SIZE, "size mismatch")
    }

    n, err := vdisk.Handle.WriteAt(data, int64(offset))
    if err != nil {
        return h.SendError(stream, ERR_IO, "write failed")
    }

    vdisk.Modified = time.Now()
    vdisk.Used += int64(n)

    go h.saveVirtualDiskMetadata(vdisk)

    response := make([]byte, 1)
    response[0] = ERR_NONE
    stream.Write(response)

    h.mu.Lock()
    h.stats.VDiskWrites++
    h.stats.VDiskBytesWr += uint64(n)
    h.mu.Unlock()

    return nil
}

func (h *DFPHandler) HandleDiskStat(header ProtocolHeader, stream quic.Stream) error {
    if header.Version < 3 {
        return h.SendError(stream, ERR_UNSUPPORTED, "command requires v3+")
    }

    var nameLen uint32
    if err := binary.Read(stream, binary.BigEndian, &nameLen); err != nil {
        return h.SendError(stream, ERR_PROTOCOL, "invalid name length")
    }

    nameBytes := make([]byte, nameLen)
    if _, err := io.ReadFull(stream, nameBytes); err != nil {
        return h.SendError(stream, ERR_IO, "failed to read disk name")
    }

    diskName := string(nameBytes)

    h.vdiskMu.RLock()
    vdisk, exists := h.vdisks[diskName]
    h.vdiskMu.RUnlock()

    if !exists {
        return h.SendError(stream, ERR_NOT_FOUND, "disk not found")
    }

    metadata := DiskMetadata{
        Name:      vdisk.Name,
        Size:      vdisk.Size,
        BlockSize: vdisk.BlockSize,
        Created:   vdisk.Created,
        Modified:  vdisk.Modified,
        Flags:     vdisk.Flags,
        Used:      vdisk.Used,
        Version:   vdisk.Version,
    }

    metaBytes := metadata.ToBytes()
    metaEncrypted, err := h.crypto.EncryptData(metaBytes)
    if err != nil {
        return h.SendError(stream, ERR_IO, "encryption failed")
    }

    encLen := uint32(len(metaEncrypted))
    if err := binary.Write(stream, binary.BigEndian, encLen); err != nil {
        return h.SendError(stream, ERR_IO, "write error")
    }

    if _, err := stream.Write(metaEncrypted); err != nil {
        return h.SendError(stream, ERR_IO, "write error")
    }

    return nil
}

func (h *DFPHandler) SendError(stream quic.Stream, code uint8, message string) error {
    h.mu.Lock()
    h.stats.Errors++
    h.mu.Unlock()

    msgBytes := []byte(message)
    msgLen := uint16(len(msgBytes))

    buf := make([]byte, 1+2+len(msgBytes))
    buf[0] = CMD_ERROR
    binary.BigEndian.PutUint16(buf[1:3], msgLen)
    copy(buf[3:], msgBytes)

    _, err := stream.Write(buf)
    return err
}

func (h *DFPHandler) validateFileName(name string) bool {
    if len(name) == 0 || len(name) > 255 {
        return false
    }

    for _, r := range name {
        if r < 32 || r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|' {
            return false
        }
    }

    return !strings.Contains(name, "..")
}

func (h *DFPHandler) GetStats() ServerStats {
    h.mu.RLock()
    defer h.mu.RUnlock()

    return *h.stats
}
