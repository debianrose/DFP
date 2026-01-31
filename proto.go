package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
    "encoding/binary"
    "encoding/pem"
    "fmt"
    "io"
    "math/big"
    "time"

    "github.com/klauspost/compress/zstd"
    "github.com/quic-go/quic-go"
    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/hkdf"
)

const (
    PROTOCOL_VERSION = 3
    MIN_VERSION      = 1
    MAX_VERSION      = 255

    CHUNK_SIZE       = 256 * 1024
    STORE_PATH       = "./storage"
    FILE_EXT         = ".dfp"
    MAX_RETRIES      = 5
    KEY_LENGTH       = 32
    SALT_LENGTH      = 32
    NONCE_LENGTH     = 12
    HEADER_MAGIC     = 0xDF50DF50

    COMPRESS_THRESHOLD = 2 * 1024 * 1024
    MAX_FILE_SIZE      = 10 * 1024 * 1024 * 1024

    CMD_UPLOAD      = 0x01
    CMD_DOWNLOAD    = 0x02
    CMD_LIST        = 0x03
    CMD_DELETE      = 0x04
    CMD_META        = 0x05
    CMD_PING        = 0x06
    CMD_DISK_CREATE = 0x07
    CMD_DISK_DELETE = 0x08
    CMD_DISK_LIST   = 0x09
    CMD_DISK_OPEN   = 0x0A
    CMD_DISK_CLOSE  = 0x0B
    CMD_DISK_READ   = 0x0C
    CMD_DISK_WRITE  = 0x0D
    CMD_DISK_STAT   = 0x0E
    CMD_ERROR       = 0xFF

    FLAG_COMPRESSED = 0x01
    FLAG_ENCRYPTED  = 0x02
    FLAG_RESUME     = 0x04
    FLAG_STREAM     = 0x08
    FLAG_VDISK      = 0x10

    ERR_NONE        = 0x00
    ERR_VERSION     = 0x01
    ERR_AUTH        = 0x02
    ERR_NOT_FOUND   = 0x03
    ERR_IO          = 0x04
    ERR_SIZE        = 0x05
    ERR_CRC         = 0x06
    ERR_PROTOCOL    = 0x07
    ERR_UNSUPPORTED = 0x08
    ERR_OVERLOAD    = 0x09
    ERR_VDISK_FULL  = 0x0A
    ERR_VDISK_BUSY  = 0x0B
    ERR_VDISK_INVAL = 0x0C
)

type ProtocolHeader struct {
    Magic      uint32
    Version    uint8
    Command    uint8
    Flags      uint16
    Sequence   uint32
    DataLength uint64
    Reserved   [16]byte
}

type ErrorResponse struct {
    Code    uint8
    Message string
}

type SessionKey struct {
    Key       []byte
    Created   time.Time
    Expires   time.Time
    SessionID [16]byte
}

type VersionNegotiator struct {
    ClientVersion uint8
    ServerVersion uint8
    Negotiated    uint8
    Compatible    bool
    Capabilities  uint32
}

func (vn *VersionNegotiator) Negotiate() bool {
    if vn.ClientVersion < MIN_VERSION || vn.ServerVersion < MIN_VERSION {
        return false
    }

    vn.Negotiated = vn.ClientVersion
    if vn.Negotiated > vn.ServerVersion {
        vn.Negotiated = vn.ServerVersion
    }

    vn.Compatible = vn.Negotiated >= MIN_VERSION &&
        vn.Negotiated <= MAX_VERSION &&
        vn.Negotiated <= vn.ClientVersion &&
        vn.Negotiated <= vn.ServerVersion

    return vn.Compatible
}

func (vn *VersionNegotiator) GetCapabilities() uint32 {
    caps := uint32(0)

    switch vn.Negotiated {
    case 1:
        caps = FLAG_ENCRYPTED
    case 2:
        caps = FLAG_ENCRYPTED | FLAG_COMPRESSED | FLAG_RESUME
    case 3:
        caps = FLAG_ENCRYPTED | FLAG_COMPRESSED | FLAG_RESUME | FLAG_VDISK
    }

    return caps
}

type ProtocolCrypto struct {
    masterKey  []byte
    sessionKey *SessionKey
    salt       []byte
    kdfSalt    []byte
}

func NewProtocolCrypto(passphrase string, salt []byte) *ProtocolCrypto {
    if salt == nil {
        salt = make([]byte, SALT_LENGTH)
        io.ReadFull(rand.Reader, salt)
    }

    kdfSalt := make([]byte, SALT_LENGTH)
    io.ReadFull(rand.Reader, kdfSalt)

    baseKey := argon2.IDKey([]byte(passphrase), salt, 4, 64*1024, 4, KEY_LENGTH*2)

    masterKey := baseKey[:KEY_LENGTH]
    hmacKey := baseKey[KEY_LENGTH:]

    pc := &ProtocolCrypto{
        masterKey: masterKey,
        salt:      salt,
        kdfSalt:   kdfSalt,
    }

    pc.sessionKey = pc.deriveSessionKey(hmacKey)
    return pc
}

func (pc *ProtocolCrypto) deriveSessionKey(hmacKey []byte) *SessionKey {
    info := []byte("DFP_SESSION_KEY_V3")
    h := hkdf.New(sha256.New, pc.masterKey, pc.kdfSalt, info)

    sessionKey := make([]byte, KEY_LENGTH)
    io.ReadFull(h, sessionKey)

    var sessionID [16]byte
    io.ReadFull(rand.Reader, sessionID[:])

    return &SessionKey{
        Key:       sessionKey,
        Created:   time.Now(),
        Expires:   time.Now().Add(24 * time.Hour),
        SessionID: sessionID,
    }
}

func (pc *ProtocolCrypto) EncryptData(data []byte) ([]byte, error) {
    fileSalt := make([]byte, SALT_LENGTH)
    io.ReadFull(rand.Reader, fileSalt)

    derivedKey := pc.deriveFileKey(fileSalt)

    block, err := aes.NewCipher(derivedKey)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    io.ReadFull(rand.Reader, nonce)

    ciphertext := gcm.Seal(nil, nonce, data, pc.sessionKey.SessionID[:])

    result := make([]byte, 0, SALT_LENGTH+len(nonce)+len(ciphertext))
    result = append(result, fileSalt...)
    result = append(result, nonce...)
    result = append(result, ciphertext...)

    return result, nil
}

func (pc *ProtocolCrypto) DecryptData(data []byte) ([]byte, error) {
    if len(data) < SALT_LENGTH+NONCE_LENGTH {
        return nil, fmt.Errorf("invalid ciphertext length")
    }

    fileSalt := data[:SALT_LENGTH]
    nonce := data[SALT_LENGTH : SALT_LENGTH+NONCE_LENGTH]
    ciphertext := data[SALT_LENGTH+NONCE_LENGTH:]

    derivedKey := pc.deriveFileKey(fileSalt)

    block, err := aes.NewCipher(derivedKey)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    plaintext, err := gcm.Open(nil, nonce, ciphertext, pc.sessionKey.SessionID[:])
    if err != nil {
        return nil, err
    }

    return plaintext, nil
}

func (pc *ProtocolCrypto) deriveFileKey(salt []byte) []byte {
    info := []byte("DFP_FILE_KEY_V3")
    h := hkdf.New(sha256.New, pc.sessionKey.Key, salt, info)

    key := make([]byte, KEY_LENGTH)
    io.ReadFull(h, key)

    return key
}

func (pc *ProtocolCrypto) CalculateChecksum(data []byte) [32]byte {
    h := sha256.New()
    h.Write(pc.sessionKey.SessionID[:])
    h.Write(data)

    var result [32]byte
    copy(result[:], h.Sum(nil))

    return result
}

type ProtocolCompressor struct {
    zstdEncoder *zstd.Encoder
    zstdDecoder *zstd.Decoder
    level       int
}

func NewProtocolCompressor() *ProtocolCompressor {
    encoder, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBetterCompression))
    decoder, _ := zstd.NewReader(nil)

    return &ProtocolCompressor{
        zstdEncoder: encoder,
        zstdDecoder: decoder,
        level:       3,
    }
}

func (pc *ProtocolCompressor) Compress(data []byte) []byte {
    if len(data) < COMPRESS_THRESHOLD {
        return data
    }

    return pc.zstdEncoder.EncodeAll(data, make([]byte, 0, len(data)/2))
}

func (pc *ProtocolCompressor) Decompress(data []byte) ([]byte, error) {
    if len(data) < COMPRESS_THRESHOLD {
        return data, nil
    }

    return pc.zstdDecoder.DecodeAll(data, nil)
}

type ProtocolConfig struct {
    MaxStreams           int64
    MaxUniStreams        int64
    StreamWindow         uint64
    ConnectionWindow     uint64
    IdleTimeout          time.Duration
    KeepAlive            time.Duration
    HandshakeTimeout     time.Duration
    MaxIncomingBytes     int64
    DisableMTUDiscovery  bool
}

func NewProtocolConfig() *ProtocolConfig {
    return &ProtocolConfig{
        MaxStreams:          100,
        MaxUniStreams:       100,
        StreamWindow:        16 * 1024 * 1024,
        ConnectionWindow:    32 * 1024 * 1024,
        IdleTimeout:         120 * time.Second,
        KeepAlive:           30 * time.Second,
        HandshakeTimeout:    10 * time.Second,
        MaxIncomingBytes:    0,
        DisableMTUDiscovery: false,
    }
}

func (pc *ProtocolConfig) ToQUICConfig() *quic.Config {
    return &quic.Config{
        MaxIncomingStreams:             pc.MaxStreams,
        MaxIncomingUniStreams:          pc.MaxUniStreams,
        InitialStreamReceiveWindow:     pc.StreamWindow,
        MaxStreamReceiveWindow:         pc.StreamWindow * 2,
        InitialConnectionReceiveWindow: pc.ConnectionWindow,
        MaxConnectionReceiveWindow:     pc.ConnectionWindow * 2,
        MaxIdleTimeout:                 pc.IdleTimeout,
        KeepAlivePeriod:                pc.KeepAlive,
        HandshakeIdleTimeout:           pc.HandshakeTimeout,
        DisablePathMTUDiscovery:        pc.DisableMTUDiscovery,
    }
}

func GenerateTLSConfig() (*tls.Config, error) {
    key, _ := rsa.GenerateKey(rand.Reader, 3072)

    template := x509.Certificate{
        SerialNumber:          big.NewInt(time.Now().UnixNano()),
        NotBefore:             time.Now(),
        NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
        KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
        BasicConstraintsValid: true,
        IsCA:                  true,
    }

    der, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)

    keyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(key),
    })

    certPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "CERTIFICATE",
        Bytes: der,
    })

    cert, _ := tls.X509KeyPair(certPEM, keyPEM)

    return &tls.Config{
        Certificates: []tls.Certificate{cert},
        NextProtos:   []string{"dfp-v3", "dfp-v2", "dfp-v1"},
        ClientAuth:   tls.RequireAnyClientCert,
        MinVersion:   tls.VersionTLS13,
        CurvePreferences: []tls.CurveID{
            tls.X25519, tls.CurveP256,
        },
        CipherSuites: []uint16{
            tls.TLS_AES_256_GCM_SHA384,
            tls.TLS_CHACHA20_POLY1305_SHA256,
            tls.TLS_AES_128_GCM_SHA256,
        },
    }, nil
}

type ProtocolHandler interface {
    HandleUpload(header ProtocolHeader, stream quic.Stream) error
    HandleDownload(header ProtocolHeader, stream quic.Stream) error
    HandleList(header ProtocolHeader, stream quic.Stream) error
    HandleDelete(header ProtocolHeader, stream quic.Stream) error
    HandleMeta(header ProtocolHeader, stream quic.Stream) error
    HandlePing(header ProtocolHeader, stream quic.Stream) error
    HandleDiskCreate(header ProtocolHeader, stream quic.Stream) error
    HandleDiskDelete(header ProtocolHeader, stream quic.Stream) error
    HandleDiskList(header ProtocolHeader, stream quic.Stream) error
    HandleDiskOpen(header ProtocolHeader, stream quic.Stream) error
    HandleDiskClose(header ProtocolHeader, stream quic.Stream) error
    HandleDiskRead(header ProtocolHeader, stream quic.Stream) error
    HandleDiskWrite(header ProtocolHeader, stream quic.Stream) error
    HandleDiskStat(header ProtocolHeader, stream quic.Stream) error
    SendError(stream quic.Stream, code uint8, message string) error
    ValidateHeader(header ProtocolHeader) error
    NegotiateVersion(clientVersion uint8) uint8
}

type FileMetadata struct {
    Name       string
    Size       int64
    Modified   time.Time
    Checksum   [32]byte
    Encrypted  bool
    Compressed bool
    Version    uint8
}

func (fm FileMetadata) ToBytes() []byte {
    buf := make([]byte, 0, 256)

    nameBytes := []byte(fm.Name)
    buf = binary.BigEndian.AppendUint32(buf, uint32(len(nameBytes)))
    buf = append(buf, nameBytes...)

    buf = binary.BigEndian.AppendUint64(buf, uint64(fm.Size))
    buf = binary.BigEndian.AppendUint64(buf, uint64(fm.Modified.UnixNano()))
    buf = append(buf, fm.Checksum[:]...)

    flags := uint8(0)
    if fm.Encrypted {
        flags |= 0x01
    }
    if fm.Compressed {
        flags |= 0x02
    }
    buf = append(buf, flags)
    buf = append(buf, fm.Version)

    return buf
}

func FileMetadataFromBytes(data []byte) (*FileMetadata, error) {
    if len(data) < 4 {
        return nil, fmt.Errorf("invalid metadata")
    }

    fm := &FileMetadata{}
    offset := 0

    nameLen := binary.BigEndian.Uint32(data[offset:])
    offset += 4

    if offset+int(nameLen) > len(data) {
        return nil, fmt.Errorf("invalid name length")
    }
    fm.Name = string(data[offset : offset+int(nameLen)])
    offset += int(nameLen)

    if offset+8 > len(data) {
        return nil, fmt.Errorf("invalid size")
    }
    fm.Size = int64(binary.BigEndian.Uint64(data[offset:]))
    offset += 8

    if offset+8 > len(data) {
        return nil, fmt.Errorf("invalid timestamp")
    }
    fm.Modified = time.Unix(0, int64(binary.BigEndian.Uint64(data[offset:])))
    offset += 8

    if offset+32 > len(data) {
        return nil, fmt.Errorf("invalid checksum")
    }
    copy(fm.Checksum[:], data[offset:offset+32])
    offset += 32

    if offset+2 > len(data) {
        return nil, fmt.Errorf("invalid flags")
    }
    flags := data[offset]
    fm.Encrypted = flags&0x01 != 0
    fm.Compressed = flags&0x02 != 0
    offset++

    fm.Version = data[offset]

    return fm, nil
}

type DiskMetadata struct {
    Name      string
    Size      int64
    BlockSize int32
    Created   time.Time
    Modified  time.Time
    Flags     uint32
    Used      int64
    Version   uint8
}

func (dm DiskMetadata) ToBytes() []byte {
    buf := make([]byte, 0, 256)

    nameBytes := []byte(dm.Name)
    buf = binary.BigEndian.AppendUint32(buf, uint32(len(nameBytes)))
    buf = append(buf, nameBytes...)

    buf = binary.BigEndian.AppendUint64(buf, uint64(dm.Size))
    buf = binary.BigEndian.AppendUint32(buf, uint32(dm.BlockSize))
    buf = binary.BigEndian.AppendUint64(buf, uint64(dm.Created.UnixNano()))
    buf = binary.BigEndian.AppendUint64(buf, uint64(dm.Modified.UnixNano()))
    buf = binary.BigEndian.AppendUint32(buf, dm.Flags)
    buf = binary.BigEndian.AppendUint64(buf, uint64(dm.Used))
    buf = append(buf, dm.Version)

    return buf
}

func DiskMetadataFromBytes(data []byte) (*DiskMetadata, error) {
    if len(data) < 4 {
        return nil, fmt.Errorf("invalid disk metadata")
    }

    dm := &DiskMetadata{}
    offset := 0

    nameLen := binary.BigEndian.Uint32(data[offset:])
    offset += 4

    if offset+int(nameLen) > len(data) {
        return nil, fmt.Errorf("invalid name length")
    }
    dm.Name = string(data[offset : offset+int(nameLen)])
    offset += int(nameLen)

    if offset+8 > len(data) {
        return nil, fmt.Errorf("invalid size")
    }
    dm.Size = int64(binary.BigEndian.Uint64(data[offset:]))
    offset += 8

    if offset+4 > len(data) {
        return nil, fmt.Errorf("invalid block size")
    }
    dm.BlockSize = int32(binary.BigEndian.Uint32(data[offset:]))
    offset += 4

    if offset+8 > len(data) {
        return nil, fmt.Errorf("invalid created timestamp")
    }
    dm.Created = time.Unix(0, int64(binary.BigEndian.Uint64(data[offset:])))
    offset += 8

    if offset+8 > len(data) {
        return nil, fmt.Errorf("invalid modified timestamp")
    }
    dm.Modified = time.Unix(0, int64(binary.BigEndian.Uint64(data[offset:])))
    offset += 8

    if offset+4 > len(data) {
        return nil, fmt.Errorf("invalid flags")
    }
    dm.Flags = binary.BigEndian.Uint32(data[offset:])
    offset += 4

    if offset+8 > len(data) {
        return nil, fmt.Errorf("invalid used")
    }
    dm.Used = int64(binary.BigEndian.Uint64(data[offset:]))
    offset += 8

    dm.Version = data[offset]

    return dm, nil
}

type ProtocolError struct {
    Code    uint8
    Message string
    Fatal   bool
}

func (pe ProtocolError) Error() string {
    return fmt.Sprintf("DFP error %d: %s", pe.Code, pe.Message)
}

func NewProtocolError(code uint8, message string) ProtocolError {
    fatal := code >= ERR_AUTH && code <= ERR_PROTOCOL
    return ProtocolError{Code: code, Message: message, Fatal: fatal}
}
