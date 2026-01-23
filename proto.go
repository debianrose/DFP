package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

const (
	CHUNK      = 128 * 1024
	STORE      = "./storage"
	EXT        = ".enc"
	MaxRetries = 5
	KeyLen     = 32
	SaltLen    = 32
	NonceLen   = 12
)

type Crypto struct {
	masterKey []byte
	salt      []byte
}

func NewCrypto(pass string) *Crypto {
	salt := make([]byte, SaltLen)
	io.ReadFull(rand.Reader, salt)
	key := argon2.IDKey([]byte(pass), salt, 3, 64*1024, 4, KeyLen)
	return &Crypto{masterKey: key, salt: salt}
}

func NewCryptoWithSalt(pass string, salt []byte) *Crypto {
	key := argon2.IDKey([]byte(pass), salt, 3, 64*1024, 4, KeyLen)
	return &Crypto{masterKey: key, salt: salt}
}

func (c *Crypto) Enc(data []byte) ([]byte, error) {
	fileSalt := make([]byte, SaltLen)
	io.ReadFull(rand.Reader, fileSalt)
	
	fileKey, _ := scrypt.Key(c.masterKey, fileSalt, 32768, 8, 1, KeyLen)
	blk, err := aes.NewCipher(fileKey)
	if err != nil {
		return nil, err
	}
	
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	
	result := make([]byte, 0, SaltLen+len(nonce)+len(ciphertext))
	result = append(result, fileSalt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)
	
	return result, nil
}

func (c *Crypto) Dec(data []byte) ([]byte, error) {
	if len(data) < SaltLen+NonceLen {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	
	fileSalt := data[:SaltLen]
	nonce := data[SaltLen : SaltLen+NonceLen]
	ciphertext := data[SaltLen+NonceLen:]
	
	fileKey, _ := scrypt.Key(c.masterKey, fileSalt, 32768, 8, 1, KeyLen)
	blk, err := aes.NewCipher(fileKey)
	if err != nil {
		return nil, err
	}
	
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	
	return plaintext, nil
}

type Compressor struct {
	enc *zstd.Encoder
	dec *zstd.Decoder
}

func NewCompressor() *Compressor {
	enc, _ := zstd.NewWriter(nil)
	dec, _ := zstd.NewReader(nil)
	return &Compressor{enc: enc, dec: dec}
}

func (c *Compressor) Zip(data []byte) []byte {
	return c.enc.EncodeAll(data, make([]byte, 0, len(data)))
}

func (c *Compressor) Unzip(data []byte) ([]byte, error) {
	return c.dec.DecodeAll(data, nil)
}

func GenTLS() (*tls.Config, error) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	t := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	cDER, _ := x509.CreateCertificate(rand.Reader, &t, &t, &k.PublicKey, k)
	kPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	cPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cDER})
	cert, _ := tls.X509KeyPair(cPEM, kPEM)
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"qft"},
	}, nil
}

func QCfg() *quic.Config {
	return &quic.Config{
		MaxIncomingStreams:             100,
		MaxIncomingUniStreams:          100,
		InitialStreamReceiveWindow:     2 * 1024 * 1024,
		MaxStreamReceiveWindow:         10 * 1024 * 1024,
		InitialConnectionReceiveWindow: 3 * 1024 * 1024,
		MaxConnectionReceiveWindow:     10 * 1024 * 1024,
		MaxIdleTimeout:                 60 * time.Second,
		KeepAlivePeriod:                20 * time.Second,
	}
}

type FileItem struct {
	Name string
	Size int64
	Time time.Time
}

func (f FileItem) Title() string       { return f.Name }
func (f FileItem) Description() string { return fmt.Sprintf("%d bytes", f.Size) }
func (f FileItem) FilterValue() string { return f.Name }
