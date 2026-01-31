package main

import (
    "context"
    "crypto/rand"
    "crypto/tls"
    "encoding/binary"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "time"

    "github.com/quic-go/quic-go"
)

type DFPClient struct {
    tlsConfig  *tls.Config
    quicConfig *quic.Config
    version    uint8
    sessionID  [16]byte
    sequence   uint32
}

type TransferStats struct {
    Bytes    uint64
    Duration time.Duration
    Speed    float64
    Errors   uint
    Retries  uint
}

func NewDFPClient() *DFPClient {
    tlsConfig, _ := GenerateTLSConfig()
    tlsConfig.InsecureSkipVerify = true
    tlsConfig.ClientAuth = tls.NoClientCert

    quicConfig := NewProtocolConfig().ToQUICConfig()

    var sessionID [16]byte
    io.ReadFull(rand.Reader, sessionID[:])

    return &DFPClient{
        tlsConfig:  tlsConfig,
        quicConfig: quicConfig,
        version:    PROTOCOL_VERSION,
        sessionID:  sessionID,
        sequence:   1,
    }
}

func (c *DFPClient) negotiateVersion(conn quic.Connection) (uint8, error) {
    stream, err := conn.OpenStreamSync(context.Background())
    if err != nil {
        return 0, err
    }
    defer stream.Close()

    header := ProtocolHeader{
        Magic:      HEADER_MAGIC,
        Version:    c.version,
        Command:    CMD_PING,
        Flags:      0,
        Sequence:   c.sequence,
        DataLength: 0,
    }
    c.sequence++

    if err := binary.Write(stream, binary.BigEndian, header); err != nil {
        return 0, err
    }

    var response ProtocolHeader
    if err := binary.Read(stream, binary.BigEndian, &response); err != nil {
        return 0, err
    }

    if response.Magic != HEADER_MAGIC {
        return 0, fmt.Errorf("invalid response")
    }

    if response.Version < MIN_VERSION || response.Version > MAX_VERSION {
        return 0, fmt.Errorf("unsupported server version: %d", response.Version)
    }

    return response.Version, nil
}

func (c *DFPClient) Upload(addr, localPath, remoteName string, crypto *ProtocolCrypto, stats *TransferStats) error {
    data, err := os.ReadFile(localPath)
    if err != nil {
        return err
    }

    var conn quic.Connection
    for i := 0; i < MAX_RETRIES; i++ {
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        conn, err = quic.DialAddr(ctx, addr, c.tlsConfig, c.quicConfig)
        cancel()

        if err == nil {
            break
        }

        stats.Retries++
        time.Sleep(time.Duration(i+1) * time.Second)
    }

    if err != nil {
        return err
    }
    defer conn.CloseWithError(0, "")

    negotiatedVersion, err := c.negotiateVersion(conn)
    if err != nil {
        return err
    }

    stream, err := conn.OpenStreamSync(context.Background())
    if err != nil {
        return err
    }
    defer stream.Close()

    flags := uint16(FLAG_ENCRYPTED)
    if len(data) > COMPRESS_THRESHOLD && negotiatedVersion >= 2 {
        flags |= FLAG_COMPRESSED
    }

    header := ProtocolHeader{
        Magic:      HEADER_MAGIC,
        Version:    negotiatedVersion,
        Command:    CMD_UPLOAD,
        Flags:      flags,
        Sequence:   c.sequence,
        DataLength: uint64(len(data)),
    }
    c.sequence++

    startTime := time.Now()

    if err := binary.Write(stream, binary.BigEndian, header); err != nil {
        stats.Errors++
        return err
    }

    nameBytes := []byte(remoteName)
    if err := binary.Write(stream, binary.BigEndian, uint32(len(nameBytes))); err != nil {
        stats.Errors++
        return err
    }

    if _, err := stream.Write(nameBytes); err != nil {
        stats.Errors++
        return err
    }

    sent := uint64(0)
    for sent < uint64(len(data)) {
        end := sent + CHUNK_SIZE
        if end > uint64(len(data)) {
            end = uint64(len(data))
        }

        n, err := stream.Write(data[sent:end])
        if err != nil {
            stats.Errors++
            return err
        }

        sent += uint64(n)
        stats.Bytes = sent
    }

    response := make([]byte, 1)
    if _, err := io.ReadFull(stream, response); err != nil {
        stats.Errors++
        return err
    }

    if response[0] != ERR_NONE {
        stats.Errors++
        return fmt.Errorf("server error: %d", response[0])
    }

    stats.Duration = time.Since(startTime)
    if stats.Duration > 0 {
        stats.Speed = float64(stats.Bytes) / stats.Duration.Seconds()
    }

    return nil
}

func (c *DFPClient) Download(addr, remoteName, localPath string, crypto *ProtocolCrypto, stats *TransferStats) error {
    var conn quic.Connection
    var err error

    for i := 0; i < MAX_RETRIES; i++ {
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        conn, err = quic.DialAddr(ctx, addr, c.tlsConfig, c.quicConfig)
        cancel()

        if err == nil {
            break
        }

        stats.Retries++
        time.Sleep(time.Duration(i+1) * time.Second)
    }

    if err != nil {
        return err
    }
    defer conn.CloseWithError(0, "")

    negotiatedVersion, err := c.negotiateVersion(conn)
    if err != nil {
        return err
    }

    stream, err := conn.OpenStreamSync(context.Background())
    if err != nil {
        return err
    }
    defer stream.Close()

    header := ProtocolHeader{
        Magic:      HEADER_MAGIC,
        Version:    negotiatedVersion,
        Command:    CMD_DOWNLOAD,
        Flags:      0,
        Sequence:   c.sequence,
        DataLength: 0,
    }
    c.sequence++

    startTime := time.Now()

    if err := binary.Write(stream, binary.BigEndian, header); err != nil {
        stats.Errors++
        return err
    }

    nameBytes := []byte(remoteName)
    if err := binary.Write(stream, binary.BigEndian, uint32(len(nameBytes))); err != nil {
        stats.Errors++
        return err
    }

    if _, err := stream.Write(nameBytes); err != nil {
        stats.Errors++
        return err
    }

    var responseHeader ProtocolHeader
    if err := binary.Read(stream, binary.BigEndian, &responseHeader); err != nil {
        stats.Errors++
        return err
    }

    if responseHeader.Command == CMD_ERROR {
        var msgLen uint16
        if err := binary.Read(stream, binary.BigEndian, &msgLen); err != nil {
            stats.Errors++
            return err
        }

        msgBytes := make([]byte, msgLen)
        if _, err := io.ReadFull(stream, msgBytes); err != nil {
            stats.Errors++
            return err
        }

        stats.Errors++
        return fmt.Errorf("server error: %s", string(msgBytes))
    }

    if responseHeader.DataLength == 0 {
        stats.Errors++
        return fmt.Errorf("empty file")
    }

    if responseHeader.DataLength > MAX_FILE_SIZE {
        stats.Errors++
        return fmt.Errorf("file too large")
    }

    buffer := make([]byte, CHUNK_SIZE)
    var received uint64
    var data []byte

    for received < responseHeader.DataLength {
        toRead := CHUNK_SIZE
        remaining := responseHeader.DataLength - received
        if remaining < uint64(toRead) {
            toRead = int(remaining)
        }

        n, err := stream.Read(buffer[:toRead])
        if err != nil && err != io.EOF {
            stats.Errors++
            return err
        }

        data = append(data, buffer[:n]...)
        received += uint64(n)
        stats.Bytes = received

        if err == io.EOF {
            break
        }
    }

    if received != responseHeader.DataLength {
        stats.Errors++
        return fmt.Errorf("incomplete download: %d/%d", received, responseHeader.DataLength)
    }

    os.MkdirAll(filepath.Dir(localPath), 0755)

    if err := os.WriteFile(localPath, data, 0644); err != nil {
        stats.Errors++
        return err
    }

    stats.Duration = time.Since(startTime)
    if stats.Duration > 0 {
        stats.Speed = float64(stats.Bytes) / stats.Duration.Seconds()
    }

    return nil
}

func (c *DFPClient) List(addr string, crypto *ProtocolCrypto) ([]FileMetadata, error) {
    conn, err := quic.DialAddr(context.Background(), addr, c.tlsConfig, c.quicConfig)
    if err != nil {
        return nil, err
    }
    defer conn.CloseWithError(0, "")

    negotiatedVersion, err := c.negotiateVersion(conn)
    if err != nil {
        return nil, err
    }

    stream, err := conn.OpenStreamSync(context.Background())
    if err != nil {
        return nil, err
    }
    defer stream.Close()

    header := ProtocolHeader{
        Magic:      HEADER_MAGIC,
        Version:    negotiatedVersion,
        Command:    CMD_LIST,
        Flags:      0,
        Sequence:   c.sequence,
        DataLength: 0,
    }
    c.sequence++

    if err := binary.Write(stream, binary.BigEndian, header); err != nil {
        return nil, err
    }

    var count uint32
    if err := binary.Read(stream, binary.BigEndian, &count); err != nil {
        return nil, err
    }

    var files []FileMetadata

    for i := uint32(0); i < count; i++ {
        var encLen uint32
        if err := binary.Read(stream, binary.BigEndian, &encLen); err != nil {
            return nil, err
        }

        encData := make([]byte, encLen)
        if _, err := io.ReadFull(stream, encData); err != nil {
            return nil, err
        }

        metaBytes, err := crypto.DecryptData(encData)
        if err != nil {
            continue
        }

        metadata, err := FileMetadataFromBytes(metaBytes)
        if err != nil {
            continue
        }

        files = append(files, *metadata)
    }

    return files, nil
}

func (c *DFPClient) Delete(addr, remoteName string, stats *TransferStats) error {
    if c.version < 2 {
        return fmt.Errorf("requires protocol version 2+")
    }

    conn, err := quic.DialAddr(context.Background(), addr, c.tlsConfig, c.quicConfig)
    if err != nil {
        return err
    }
    defer conn.CloseWithError(0, "")

    negotiatedVersion, err := c.negotiateVersion(conn)
    if err != nil {
        return err
    }

    if negotiatedVersion < 2 {
        return fmt.Errorf("server requires version 2+")
    }

    stream, err := conn.OpenStreamSync(context.Background())
    if err != nil {
        return err
    }
    defer stream.Close()

    header := ProtocolHeader{
        Magic:      HEADER_MAGIC,
        Version:    negotiatedVersion,
        Command:    CMD_DELETE,
        Flags:      0,
        Sequence:   c.sequence,
        DataLength: 0,
    }
    c.sequence++

    if err := binary.Write(stream, binary.BigEndian, header); err != nil {
        stats.Errors++
        return err
    }

    nameBytes := []byte(remoteName)
    if err := binary.Write(stream, binary.BigEndian, uint32(len(nameBytes))); err != nil {
        stats.Errors++
        return err
    }

    if _, err := stream.Write(nameBytes); err != nil {
        stats.Errors++
        return err
    }

    response := make([]byte, 1)
    if _, err := io.ReadFull(stream, response); err != nil {
        stats.Errors++
        return err
    }

    if response[0] != ERR_NONE {
        stats.Errors++
        return fmt.Errorf("server error: %d", response[0])
    }

    return nil
}

func (c *DFPClient) GetMetadata(addr, remoteName string, crypto *ProtocolCrypto) (*FileMetadata, error) {
    if c.version < 2 {
        return nil, fmt.Errorf("requires protocol version 2+")
    }

    conn, err := quic.DialAddr(context.Background(), addr, c.tlsConfig, c.quicConfig)
    if err != nil {
        return nil, err
    }
    defer conn.CloseWithError(0, "")

    negotiatedVersion, err := c.negotiateVersion(conn)
    if err != nil {
        return nil, err
    }

    if negotiatedVersion < 2 {
        return nil, fmt.Errorf("server requires version 2+")
    }

    stream, err := conn.OpenStreamSync(context.Background())
    if err != nil {
        return nil, err
    }
    defer stream.Close()

    header := ProtocolHeader{
        Magic:      HEADER_MAGIC,
        Version:    negotiatedVersion,
        Command:    CMD_META,
        Flags:      0,
        Sequence:   c.sequence,
        DataLength: 0,
    }
    c.sequence++

    if err := binary.Write(stream, binary.BigEndian, header); err != nil {
        return nil, err
    }

    nameBytes := []byte(remoteName)
    if err := binary.Write(stream, binary.BigEndian, uint32(len(nameBytes))); err != nil {
        return nil, err
    }

    if _, err := stream.Write(nameBytes); err != nil {
        return nil, err
    }

    var encLen uint32
    if err := binary.Read(stream, binary.BigEndian, &encLen); err != nil {
        return nil, err
    }

    encData := make([]byte, encLen)
    if _, err := io.ReadFull(stream, encData); err != nil {
        return nil, err
    }

    metaBytes, err := crypto.DecryptData(encData)
    if err != nil {
        return nil, err
    }

    return FileMetadataFromBytes(metaBytes)
}

func (c *DFPClient) Ping(addr string) (time.Duration, error) {
    conn, err := quic.DialAddr(context.Background(), addr, c.tlsConfig, c.quicConfig)
    if err != nil {
        return 0, err
    }
    defer conn.CloseWithError(0, "")

    negotiatedVersion, err := c.negotiateVersion(conn)
    if err != nil {
        return 0, err
    }

    stream, err := conn.OpenStreamSync(context.Background())
    if err != nil {
        return 0, err
    }
    defer stream.Close()

    header := ProtocolHeader{
        Magic:      HEADER_MAGIC,
        Version:    negotiatedVersion,
        Command:    CMD_PING,
        Flags:      0,
        Sequence:   c.sequence,
        DataLength: 0,
    }
    c.sequence++

    start := time.Now()

    if err := binary.Write(stream, binary.BigEndian, header); err != nil {
        return 0, err
    }

    var response ProtocolHeader
    if err := binary.Read(stream, binary.BigEndian, &response); err != nil {
        return 0, err
    }

    if response.Command != CMD_PING {
        return 0, fmt.Errorf("invalid response")
    }

    return time.Since(start), nil
}

func (c *DFPClient) SetVersion(version uint8) error {
    if version < MIN_VERSION || version > MAX_VERSION {
        return fmt.Errorf("invalid version: %d", version)
    }

    c.version = version
    return nil
}

func (c *DFPClient) GetVersion() uint8 {
    return c.version
}

func (c *DFPClient) DiskCreate(addr, diskName string, size, blockSize uint32, stats *TransferStats) error {
    if c.version < 3 {
        return fmt.Errorf("requires protocol version 3+")
    }

    conn, err := quic.DialAddr(context.Background(), addr, c.tlsConfig, c.quicConfig)
    if err != nil {
        return err
    }
    defer conn.CloseWithError(0, "")

    negotiatedVersion, err := c.negotiateVersion(conn)
    if err != nil {
        return err
    }

    if negotiatedVersion < 3 {
        return fmt.Errorf("server requires version 3+")
    }

    stream, err := conn.OpenStreamSync(context.Background())
    if err != nil {
        return err
    }
    defer stream.Close()

    header := ProtocolHeader{
        Magic:      HEADER_MAGIC,
        Version:    negotiatedVersion,
        Command:    CMD_DISK_CREATE,
        Flags:      FLAG_VDISK,
        Sequence:   c.sequence,
        DataLength: 0,
    }
    c.sequence++

    if err := binary.Write(stream, binary.BigEndian, header); err != nil {
        stats.Errors++
        return err
    }

    nameBytes := []byte(diskName)
    if err := binary.Write(stream, binary.BigEndian, uint32(len(nameBytes))); err != nil {
        stats.Errors++
        return err
    }

    if _, err := stream.Write(nameBytes); err != nil {
        stats.Errors++
        return err
    }

    if err := binary.Write(stream, binary.BigEndian, size); err != nil {
        stats.Errors++
        return err
    }

    if err := binary.Write(stream, binary.BigEndian, blockSize); err != nil {
        stats.Errors++
        return err
    }

    response := make([]byte, 1)
    if _, err := io.ReadFull(stream, response); err != nil {
        stats.Errors++
        return err
    }

    if response[0] != ERR_NONE {
        stats.Errors++
        return fmt.Errorf("server error: %d", response[0])
    }

    return nil
}

func (c *DFPClient) DiskDelete(addr, diskName string, stats *TransferStats) error {
    if c.version < 3 {
        return fmt.Errorf("requires protocol version 3+")
    }

    conn, err := quic.DialAddr(context.Background(), addr, c.tlsConfig, c.quicConfig)
    if err != nil {
        return err
    }
    defer conn.CloseWithError(0, "")

    negotiatedVersion, err := c.negotiateVersion(conn)
    if err != nil {
        return err
    }

    if negotiatedVersion < 3 {
        return fmt.Errorf("server requires version 3+")
    }

    stream, err := conn.OpenStreamSync(context.Background())
    if err != nil {
        return err
    }
    defer stream.Close()

    header := ProtocolHeader{
        Magic:      HEADER_MAGIC,
        Version:    negotiatedVersion,
        Command:    CMD_DISK_DELETE,
        Flags:      FLAG_VDISK,
        Sequence:   c.sequence,
        DataLength: 0,
    }
    c.sequence++

    if err := binary.Write(stream, binary.BigEndian, header); err != nil {
        stats.Errors++
        return err
    }

    nameBytes := []byte(diskName)
    if err := binary.Write(stream, binary.BigEndian, uint32(len(nameBytes))); err != nil {
        stats.Errors++
        return err
    }

    if _, err := stream.Write(nameBytes); err != nil {
        stats.Errors++
        return err
    }

    response := make([]byte, 1)
    if _, err := io.ReadFull(stream, response); err != nil {
        stats.Errors++
        return err
    }

    if response[0] != ERR_NONE {
        stats.Errors++
        return fmt.Errorf("server error: %d", response[0])
    }

    return nil
}

func (c *DFPClient) DiskList(addr string, crypto *ProtocolCrypto) ([]DiskMetadata, error) {
    if c.version < 3 {
        return nil, fmt.Errorf("requires protocol version 3+")
    }

    conn, err := quic.DialAddr(context.Background(), addr, c.tlsConfig, c.quicConfig)
    if err != nil {
        return nil, err
    }
    defer conn.CloseWithError(0, "")

    negotiatedVersion, err := c.negotiateVersion(conn)
    if err != nil {
        return nil, err
    }

    if negotiatedVersion < 3 {
        return nil, fmt.Errorf("server requires version 3+")
    }

    stream, err := conn.OpenStreamSync(context.Background())
    if err != nil {
        return nil, err
    }
    defer stream.Close()

    header := ProtocolHeader{
        Magic:      HEADER_MAGIC,
        Version:    negotiatedVersion,
        Command:    CMD_DISK_LIST,
        Flags:      FLAG_VDISK,
        Sequence:   c.sequence,
        DataLength: 0,
    }
    c.sequence++

    if err := binary.Write(stream, binary.BigEndian, header); err != nil {
        return nil, err
    }

    var count uint32
    if err := binary.Read(stream, binary.BigEndian, &count); err != nil {
        return nil, err
    }

    var disks []DiskMetadata

    for i := uint32(0); i < count; i++ {
        var encLen uint32
        if err := binary.Read(stream, binary.BigEndian, &encLen); err != nil {
            return nil, err
        }

        encData := make([]byte, encLen)
        if _, err := io.ReadFull(stream, encData); err != nil {
            return nil, err
        }

        metaBytes, err := crypto.DecryptData(encData)
        if err != nil {
            continue
        }

        metadata, err := DiskMetadataFromBytes(metaBytes)
        if err != nil {
            continue
        }

        disks = append(disks, *metadata)
    }

    return disks, nil
}

func (c *DFPClient) DiskOpen(addr, diskName string, stats *TransferStats) error {
    if c.version < 3 {
        return fmt.Errorf("requires protocol version 3+")
    }

    conn, err := quic.DialAddr(context.Background(), addr, c.tlsConfig, c.quicConfig)
    if err != nil {
        return err
    }
    defer conn.CloseWithError(0, "")

    negotiatedVersion, err := c.negotiateVersion(conn)
    if err != nil {
        return err
    }

    if negotiatedVersion < 3 {
        return fmt.Errorf("server requires version 3+")
    }

    stream, err := conn.OpenStreamSync(context.Background())
    if err != nil {
        return err
    }
    defer stream.Close()

    header := ProtocolHeader{
        Magic:      HEADER_MAGIC,
        Version:    negotiatedVersion,
        Command:    CMD_DISK_OPEN,
        Flags:      FLAG_VDISK,
        Sequence:   c.sequence,
        DataLength: 0,
    }
    c.sequence++

    if err := binary.Write(stream, binary.BigEndian, header); err != nil {
        stats.Errors++
        return err
    }

    nameBytes := []byte(diskName)
    if err := binary.Write(stream, binary.BigEndian, uint32(len(nameBytes))); err != nil {
        stats.Errors++
        return err
    }

    if _, err := stream.Write(nameBytes); err != nil {
        stats.Errors++
        return err
    }

    response := make([]byte, 1)
    if _, err := io.ReadFull(stream, response); err != nil {
        stats.Errors++
        return err
    }

    if response[0] != ERR_NONE {
        stats.Errors++
        return fmt.Errorf("server error: %d", response[0])
    }

    return nil
}

func (c *DFPClient) DiskClose(addr, diskName string, stats *TransferStats) error {
    if c.version < 3 {
        return fmt.Errorf("requires protocol version 3+")
    }

    conn, err := quic.DialAddr(context.Background(), addr, c.tlsConfig, c.quicConfig)
    if err != nil {
        return err
    }
    defer conn.CloseWithError(0, "")

    negotiatedVersion, err := c.negotiateVersion(conn)
    if err != nil {
        return err
    }

    if negotiatedVersion < 3 {
        return fmt.Errorf("server requires version 3+")
    }

    stream, err := conn.OpenStreamSync(context.Background())
    if err != nil {
        return err
    }
    defer stream.Close()

    header := ProtocolHeader{
        Magic:      HEADER_MAGIC,
        Version:    negotiatedVersion,
        Command:    CMD_DISK_CLOSE,
        Flags:      FLAG_VDISK,
        Sequence:   c.sequence,
        DataLength: 0,
    }
    c.sequence++

    if err := binary.Write(stream, binary.BigEndian, header); err != nil {
        stats.Errors++
        return err
    }

    nameBytes := []byte(diskName)
    if err := binary.Write(stream, binary.BigEndian, uint32(len(nameBytes))); err != nil {
        stats.Errors++
        return err
    }

    if _, err := stream.Write(nameBytes); err != nil {
        stats.Errors++
        return err
    }

    response := make([]byte, 1)
    if _, err := io.ReadFull(stream, response); err != nil {
        stats.Errors++
        return err
    }

    if response[0] != ERR_NONE {
        stats.Errors++
        return fmt.Errorf("server error: %d", response[0])
    }

    return nil
}

func (c *DFPClient) DiskRead(addr, diskName string, offset, length uint64, stats *TransferStats) ([]byte, error) {
    if c.version < 3 {
        return nil, fmt.Errorf("requires protocol version 3+")
    }

    conn, err := quic.DialAddr(context.Background(), addr, c.tlsConfig, c.quicConfig)
    if err != nil {
        return nil, err
    }
    defer conn.CloseWithError(0, "")

    negotiatedVersion, err := c.negotiateVersion(conn)
    if err != nil {
        return nil, err
    }

    if negotiatedVersion < 3 {
        return nil, fmt.Errorf("server requires version 3+")
    }

    stream, err := conn.OpenStreamSync(context.Background())
    if err != nil {
        return nil, err
    }
    defer stream.Close()

    header := ProtocolHeader{
        Magic:      HEADER_MAGIC,
        Version:    negotiatedVersion,
        Command:    CMD_DISK_READ,
        Flags:      FLAG_VDISK,
        Sequence:   c.sequence,
        DataLength: length,
    }
    c.sequence++

    startTime := time.Now()

    if err := binary.Write(stream, binary.BigEndian, header); err != nil {
        stats.Errors++
        return nil, err
    }

    nameBytes := []byte(diskName)
    if err := binary.Write(stream, binary.BigEndian, uint32(len(nameBytes))); err != nil {
        stats.Errors++
        return nil, err
    }

    if _, err := stream.Write(nameBytes); err != nil {
        stats.Errors++
        return nil, err
    }

    if err := binary.Write(stream, binary.BigEndian, offset); err != nil {
        stats.Errors++
        return nil, err
    }

    if err := binary.Write(stream, binary.BigEndian, length); err != nil {
        stats.Errors++
        return nil, err
    }

    var responseHeader ProtocolHeader
    if err := binary.Read(stream, binary.BigEndian, &responseHeader); err != nil {
        stats.Errors++
        return nil, err
    }

    if responseHeader.Command == CMD_ERROR {
        var msgLen uint16
        if err := binary.Read(stream, binary.BigEndian, &msgLen); err != nil {
            stats.Errors++
            return nil, err
        }

        msgBytes := make([]byte, msgLen)
        if _, err := io.ReadFull(stream, msgBytes); err != nil {
            stats.Errors++
            return nil, err
        }

        stats.Errors++
        return nil, fmt.Errorf("server error: %s", string(msgBytes))
    }

    if responseHeader.DataLength == 0 {
        return []byte{}, nil
    }

    if responseHeader.DataLength > MAX_FILE_SIZE {
        stats.Errors++
        return nil, fmt.Errorf("data too large")
    }

    buffer := make([]byte, CHUNK_SIZE)
    var received uint64
    var data []byte

    for received < responseHeader.DataLength {
        toRead := CHUNK_SIZE
        remaining := responseHeader.DataLength - received
        if remaining < uint64(toRead) {
            toRead = int(remaining)
        }

        n, err := stream.Read(buffer[:toRead])
        if err != nil && err != io.EOF {
            stats.Errors++
            return nil, err
        }

        data = append(data, buffer[:n]...)
        received += uint64(n)
        stats.Bytes = received

        if err == io.EOF {
            break
        }
    }

    if received != responseHeader.DataLength {
        stats.Errors++
        return nil, fmt.Errorf("incomplete read: %d/%d", received, responseHeader.DataLength)
    }

    stats.Duration = time.Since(startTime)
    if stats.Duration > 0 {
        stats.Speed = float64(stats.Bytes) / stats.Duration.Seconds()
    }

    return data, nil
}

func (c *DFPClient) DiskWrite(addr, diskName string, offset uint64, data []byte, stats *TransferStats) error {
    if c.version < 3 {
        return fmt.Errorf("requires protocol version 3+")
    }

    conn, err := quic.DialAddr(context.Background(), addr, c.tlsConfig, c.quicConfig)
    if err != nil {
        return err
    }
    defer conn.CloseWithError(0, "")

    negotiatedVersion, err := c.negotiateVersion(conn)
    if err != nil {
        return err
    }

    if negotiatedVersion < 3 {
        return fmt.Errorf("server requires version 3+")
    }

    stream, err := conn.OpenStreamSync(context.Background())
    if err != nil {
        return err
    }
    defer stream.Close()

    header := ProtocolHeader{
        Magic:      HEADER_MAGIC,
        Version:    negotiatedVersion,
        Command:    CMD_DISK_WRITE,
        Flags:      FLAG_VDISK,
        Sequence:   c.sequence,
        DataLength: uint64(len(data)),
    }
    c.sequence++

    startTime := time.Now()

    if err := binary.Write(stream, binary.BigEndian, header); err != nil {
        stats.Errors++
        return err
    }

    nameBytes := []byte(diskName)
    if err := binary.Write(stream, binary.BigEndian, uint32(len(nameBytes))); err != nil {
        stats.Errors++
        return err
    }

    if _, err := stream.Write(nameBytes); err != nil {
        stats.Errors++
        return err
    }

    if err := binary.Write(stream, binary.BigEndian, offset); err != nil {
        stats.Errors++
        return err
    }

    sent := uint64(0)
    for sent < uint64(len(data)) {
        end := sent + CHUNK_SIZE
        if end > uint64(len(data)) {
            end = uint64(len(data))
        }

        n, err := stream.Write(data[sent:end])
        if err != nil {
            stats.Errors++
            return err
        }

        sent += uint64(n)
        stats.Bytes = sent
    }

    response := make([]byte, 1)
    if _, err := io.ReadFull(stream, response); err != nil {
        stats.Errors++
        return err
    }

    if response[0] != ERR_NONE {
        stats.Errors++
        return fmt.Errorf("server error: %d", response[0])
    }

    stats.Duration = time.Since(startTime)
    if stats.Duration > 0 {
        stats.Speed = float64(stats.Bytes) / stats.Duration.Seconds()
    }

    return nil
}

func (c *DFPClient) DiskStat(addr, diskName string, crypto *ProtocolCrypto) (*DiskMetadata, error) {
    if c.version < 3 {
        return nil, fmt.Errorf("requires protocol version 3+")
    }

    conn, err := quic.DialAddr(context.Background(), addr, c.tlsConfig, c.quicConfig)
    if err != nil {
        return nil, err
    }
    defer conn.CloseWithError(0, "")

    negotiatedVersion, err := c.negotiateVersion(conn)
    if err != nil {
        return nil, err
    }

    if negotiatedVersion < 3 {
        return nil, fmt.Errorf("server requires version 3+")
    }

    stream, err := conn.OpenStreamSync(context.Background())
    if err != nil {
        return nil, err
    }
    defer stream.Close()

    header := ProtocolHeader{
        Magic:      HEADER_MAGIC,
        Version:    negotiatedVersion,
        Command:    CMD_DISK_STAT,
        Flags:      FLAG_VDISK,
        Sequence:   c.sequence,
        DataLength: 0,
    }
    c.sequence++

    if err := binary.Write(stream, binary.BigEndian, header); err != nil {
        return nil, err
    }

    nameBytes := []byte(diskName)
    if err := binary.Write(stream, binary.BigEndian, uint32(len(nameBytes))); err != nil {
        return nil, err
    }

    if _, err := stream.Write(nameBytes); err != nil {
        return nil, err
    }

    var encLen uint32
    if err := binary.Read(stream, binary.BigEndian, &encLen); err != nil {
        return nil, err
    }

    encData := make([]byte, encLen)
    if _, err := io.ReadFull(stream, encData); err != nil {
        return nil, err
    }

    metaBytes, err := crypto.DecryptData(encData)
    if err != nil {
        return nil, err
    }

    return DiskMetadataFromBytes(metaBytes)
}
