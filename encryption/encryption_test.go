package libraryEncryption

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValueOrDefault(t *testing.T) {
	bigger := func(a, b int) bool {
		// t.Log(1)
		return a > b
	}
	smaller := func(a, b int) bool {
		return a < b
	}
	productIsOdd := func(a, b int) bool {
		return (a*b)%2 == 0
	}
	require.Equal(t, ValueOrDefault(0, 100, nil), 100)
	require.Equal(t, ValueOrDefault(1, 100, nil), 1)
	require.Equal(t, ValueOrDefault(-1, 100, nil), 100)
	require.Equal(t, ValueOrDefault(0, 100, bigger), 100)
	require.Equal(t, ValueOrDefault(101, 100, bigger), 101)
	require.Equal(t, ValueOrDefault(101, 100, smaller), 100)
	require.Equal(t, ValueOrDefault(56, 100, smaller), 56)
	require.Equal(t, ValueOrDefault(3, 9, productIsOdd), 9)
	require.Equal(t, ValueOrDefault(3, 10, productIsOdd), 3)
}

func TestED(t *testing.T) {
	salt := []byte("0123456789abcdef")
	passphrase := []byte("0123456789abcdef0123456789abcdef")
	ed, err := NewED(passphrase, salt, 0, 0, 46)
	require.NoError(t, err)
	// require.Equal(t, ed.iterations, iterations)
	// require.Equal(t, ed.keyLength, keyLength)
	require.Equal(t, ed.nonceLength, 46)
}

func TestEncryptor(t *testing.T) {
	salt := []byte("0123456789abcdef")
	data := []byte(strings.Repeat("a", 666))
	passphrase := []byte("0123456789abcdef0123456789abcdef")
	ed, err := NewED(passphrase, salt, 0, 0, 8)
	require.NoError(t, err)
	encrypted, err := ed.EncryptAES(data)
	require.NoError(t, err)
	decrypted, err := ed.DecryptAES(encrypted)
	require.NoError(t, err)
	require.Equal(t, data, decrypted)
}

func TestEncryptorNonceUniqueness(t *testing.T) {
	salt := []byte("0123456789abcdef")
	data := []byte(strings.Repeat("b", 64))
	passphrase := []byte("0123456789abcdef0123456789abcdef")

	ed, err := NewED(passphrase, salt, 0, 0, 8)
	require.NoError(t, err)

	encrypted1, err := ed.EncryptAES(data)
	require.NoError(t, err)
	encrypted2, err := ed.EncryptAES(data)
	require.NoError(t, err)

	require.NotEqual(t, encrypted1, encrypted2)
}

func TestDecryptAESSadPath(t *testing.T) {
	salt := []byte("0123456789abcdef")
	data := []byte(strings.Repeat("c", 64))
	passphrase := []byte("0123456789abcdef0123456789abcdef")

	ed, err := NewED(passphrase, salt, 0, 0, 8)
	require.NoError(t, err)
	encrypted, err := ed.EncryptAES(data)
	require.NoError(t, err)

	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[len(tampered)-1] ^= 0xFF
	_, err = ed.DecryptAES(tampered)
	require.Error(t, err)

	short := encrypted[:ed.nonceLength-1]
	_, err = ed.DecryptAES(short)
	require.Error(t, err)

	otherED, err := NewED([]byte("fedcba9876543210fedcba9876543210"), []byte("fedcba9876543210"), 0, 0, 8)
	require.NoError(t, err)
	_, err = otherED.DecryptAES(encrypted)
	require.Error(t, err)
}

func TestDecryptAESShortCiphertext(t *testing.T) {
	salt := []byte("0123456789abcdef")
	passphrase := []byte("0123456789abcdef0123456789abcdef")

	ed, err := NewED(passphrase, salt, 0, 0, 8)
	require.NoError(t, err)

	_, err = ed.DecryptAES(nil)
	require.Error(t, err)

	short := make([]byte, ed.nonceLength-1)
	_, err = ed.DecryptAES(short)
	require.Error(t, err)
}

func BenchmarkEncryptor(b *testing.B) {
	salt := []byte("0123456789abcdef")
	data := []byte(strings.Repeat("a", 666))
	passphrase := []byte("0123456789abcdef0123456789abcdef")
	ed, err := NewED(passphrase, salt, 0, 0, 8)
	require.NoError(b, err)
	for b.Loop() {
		encrypted, _ := ed.EncryptAES(data)
		_, _ = ed.DecryptAES(encrypted)

	}
}
