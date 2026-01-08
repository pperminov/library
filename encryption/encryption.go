package libraryEncryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/binary"

	libraryErrors "github.com/pperminov/library/errors"
	libraryNumbers "github.com/pperminov/library/numbers"
	"golang.org/x/crypto/pbkdf2"
)

const (
	keyLength   = 32
	nonceLength = 12
	iterations  = 100000
)

func ValueOrDefault[T int | int64 | uint | uint64](value, defaults T, f func(T, T) bool) T {
	if value <= 0 || (f != nil && !f(value, defaults)) {
		return defaults
	}
	return value
}

func NewED(secret, salt []byte, keyLengthUser, iterationsUser, nonceLengthUser int) (*ED, error) {
	randomNonce, err := libraryNumbers.RandomUint64()
	if err != nil {
		return nil, err
	}
	return &ED{
		nonceLength: ValueOrDefault(nonceLengthUser, nonceLength, func(a, b int) bool { return a > b }),
		key:         pbkdf2.Key(secret, salt, ValueOrDefault(iterationsUser, iterations, nil), ValueOrDefault(keyLengthUser, keyLength, nil), sha512.New),
		nonce:       randomNonce,
	}, nil
}

type ED struct {
	key         []byte
	nonce       uint64
	nonceLength int
}

func (e *ED) getNonce() []byte {
	bytes := make([]byte, e.nonceLength)
	binary.BigEndian.PutUint64(bytes[4:], e.nonce)
	e.nonce++
	return bytes
}

func (e *ED) EncryptAES(plaintextBytes []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := e.getNonce()
	return aesGCM.Seal(nonce, nonce, plaintextBytes, nil), nil
}

func (e *ED) DecryptAES(encryptedBytes []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(encryptedBytes) < e.nonceLength {
		return nil, libraryErrors.WrapError("ciphertext too short", nil)
	}
	nonce, ciphertext := encryptedBytes[:e.nonceLength], encryptedBytes[e.nonceLength:]

	return aesGCM.Open(nil, nonce, ciphertext, nil)
}
