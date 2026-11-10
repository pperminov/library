package hellpki

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"

	libraryErrors "github.com/pperminov/library/errors"
	libraryNetwork "github.com/pperminov/library/network"
)

const (
	p256PublicKeySize = 65
	gcmNonceSize      = 12
	signatureLenSize  = 2
	aesKeySize        = 32
)

type Config struct {
	LocalPrivateKey *ecdsa.PrivateKey
	RemotePublicKey *ecdsa.PublicKey
	Context         []byte
	SignMessages    bool
	VerifyMessages  bool
}

func MakeAHellCirclePKI(conn libraryNetwork.GenericConnection, cfg Config) (libraryNetwork.GenericConnection, error) {
	if cfg.LocalPrivateKey == nil {
		return nil, libraryErrors.NewError("local private key is required")
	}
	if cfg.RemotePublicKey == nil {
		return nil, libraryErrors.NewError("remote public key is required")
	}
	if cfg.SignMessages && cfg.LocalPrivateKey == nil {
		return nil, libraryErrors.NewError("signing requires a local private key")
	}
	if cfg.VerifyMessages && cfg.RemotePublicKey == nil {
		return nil, libraryErrors.NewError("verification requires a remote public key")
	}
	if cfg.LocalPrivateKey.Curve != elliptic.P256() || cfg.RemotePublicKey.Curve != elliptic.P256() {
		return nil, libraryErrors.NewError("only P-256 keys are supported")
	}

	return &HellCirclePKI{
		connection: conn,
		config:     cfg,
	}, nil
}

type HellCirclePKI struct {
	connection libraryNetwork.GenericConnection
	config     Config
}

func (m HellCirclePKI) Read(b []byte) (int, error) {
	body, err := readFrame(m.connection)
	if err != nil {
		return 0, err
	}

	ephemeralPub, nonce, ciphertext, signature, err := parseFrame(body)
	if err != nil {
		return 0, err
	}

	if m.config.VerifyMessages {
		if len(signature) == 0 {
			return 0, libraryErrors.NewError("missing signature")
		}
		if err := verifySignature(m.config.RemotePublicKey, ephemeralPub, nonce, ciphertext, signature); err != nil {
			return 0, err
		}
	}

	plaintext, err := decryptPayload(m.config.LocalPrivateKey, ephemeralPub, nonce, ciphertext, m.config.Context)
	if err != nil {
		return 0, err
	}

	if len(b) < len(plaintext) {
		return 0, io.ErrShortBuffer
	}
	return copy(b, plaintext), nil
}

func (m HellCirclePKI) Write(b []byte) (int, error) {
	ephemeralPub, nonce, ciphertext, err := encryptPayload(m.config.RemotePublicKey, b, m.config.Context)
	if err != nil {
		return 0, err
	}

	signature := []byte{}
	if m.config.SignMessages {
		signature, err = signPayload(m.config.LocalPrivateKey, ephemeralPub, nonce, ciphertext)
		if err != nil {
			return 0, err
		}
	}

	body, err := buildFrame(ephemeralPub, nonce, ciphertext, signature)
	if err != nil {
		return 0, err
	}

	if err := writeFrame(m.connection, body); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (m HellCirclePKI) Close() error {
	return m.connection.Close()
}

func writeFrame(conn libraryNetwork.GenericConnection, body []byte) error {
	length := uint32(len(body))
	if err := binary.Write(conn, binary.BigEndian, length); err != nil {
		return err
	}
	_, err := conn.Write(body)
	return err
}

func readFrame(conn libraryNetwork.GenericConnection) ([]byte, error) {
	var length uint32
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, errors.New("empty frame")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

func buildFrame(ephemeralPub, nonce, ciphertext, signature []byte) ([]byte, error) {
	if len(ephemeralPub) != p256PublicKeySize {
		return nil, errors.New("unexpected public key size")
	}
	if len(nonce) != gcmNonceSize {
		return nil, errors.New("unexpected nonce size")
	}
	if len(signature) > int(^uint16(0)) {
		return nil, errors.New("signature too large")
	}

	body := make([]byte, 0, p256PublicKeySize+gcmNonceSize+len(ciphertext)+len(signature)+signatureLenSize)
	body = append(body, ephemeralPub...)
	body = append(body, nonce...)
	body = append(body, ciphertext...)
	body = append(body, signature...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(signature)))
	return body, nil
}

func parseFrame(body []byte) ([]byte, []byte, []byte, []byte, error) {
	minSize := p256PublicKeySize + gcmNonceSize + signatureLenSize
	if len(body) < minSize {
		return nil, nil, nil, nil, errors.New("frame too short")
	}

	ephemeralPub := body[:p256PublicKeySize]
	nonceStart := p256PublicKeySize
	nonceEnd := nonceStart + gcmNonceSize
	nonce := body[nonceStart:nonceEnd]
	payload := body[nonceEnd:]
	if len(payload) < signatureLenSize {
		return nil, nil, nil, nil, errors.New("frame missing signature length")
	}

	sigLen := int(binary.BigEndian.Uint16(payload[len(payload)-signatureLenSize:]))
	if sigLen > len(payload)-signatureLenSize {
		return nil, nil, nil, nil, errors.New("invalid signature length")
	}

	signature := payload[len(payload)-signatureLenSize-sigLen : len(payload)-signatureLenSize]
	ciphertext := payload[:len(payload)-signatureLenSize-sigLen]
	return ephemeralPub, nonce, ciphertext, signature, nil
}

func encryptPayload(remotePub *ecdsa.PublicKey, plaintext, context []byte) ([]byte, []byte, []byte, error) {
	curve := ecdh.P256()
	ephemeralPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	ephemeralPub := ephemeralPriv.PublicKey().Bytes()

	remoteECDH, err := ecdsaPublicKeyToECDH(remotePub)
	if err != nil {
		return nil, nil, nil, err
	}
	sharedSecret, err := ephemeralPriv.ECDH(remoteECDH)
	if err != nil {
		return nil, nil, nil, err
	}

	key, err := deriveKey(sharedSecret, context)
	if err != nil {
		return nil, nil, nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, err
	}
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	return ephemeralPub, nonce, ciphertext, nil
}

func decryptPayload(localPriv *ecdsa.PrivateKey, ephemeralPub, nonce, ciphertext, context []byte) ([]byte, error) {
	localECDH, err := ecdsaPrivateKeyToECDH(localPriv)
	if err != nil {
		return nil, err
	}
	remoteECDH, err := ecdh.P256().NewPublicKey(ephemeralPub)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := localECDH.ECDH(remoteECDH)
	if err != nil {
		return nil, err
	}

	key, err := deriveKey(sharedSecret, context)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aesGCM.NonceSize() {
		return nil, errors.New("invalid nonce size")
	}
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}

func deriveKey(sharedSecret, context []byte) ([]byte, error) {
	salt := []byte("hellpki-p256-salt")
	info := append([]byte("hellpki-p256"), context...)

	hkdfReader := hkdf.New(func() hash.Hash { return sha256.New() }, sharedSecret, salt, info)
	key := make([]byte, aesKeySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func signPayload(priv *ecdsa.PrivateKey, ephemeralPub, nonce, ciphertext []byte) ([]byte, error) {
	hash := sha256.New()
	hash.Write(ephemeralPub)
	hash.Write(nonce)
	hash.Write(ciphertext)
	digest := hash.Sum(nil)

	return ecdsa.SignASN1(rand.Reader, priv, digest)
}

func verifySignature(pub *ecdsa.PublicKey, ephemeralPub, nonce, ciphertext, signature []byte) error {
	hash := sha256.New()
	hash.Write(ephemeralPub)
	hash.Write(nonce)
	hash.Write(ciphertext)
	digest := hash.Sum(nil)

	if !ecdsa.VerifyASN1(pub, digest, signature) {
		return errors.New("signature verification failed")
	}
	return nil
}

func ecdsaPublicKeyToECDH(pub *ecdsa.PublicKey) (*ecdh.PublicKey, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return nil, errors.New("invalid P-256 public key")
	}
	encoded := elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)
	return ecdh.P256().NewPublicKey(encoded)
}

func ecdsaPrivateKeyToECDH(priv *ecdsa.PrivateKey) (*ecdh.PrivateKey, error) {
	if priv == nil || priv.Curve != elliptic.P256() {
		return nil, errors.New("invalid P-256 private key")
	}
	size := (priv.Params().N.BitLen() + 7) / 8
	scalar := make([]byte, size)
	priv.D.FillBytes(scalar)
	return ecdh.P256().NewPrivateKey(scalar)
}
