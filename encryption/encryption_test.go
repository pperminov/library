package libraryEncryption

import (
	"testing"

	"github.com/stretchr/testify/require"

	libraryStrings "github.com/pperminov/library/strings"
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
	salt := []byte(libraryStrings.RandString(16))
	passphrase := []byte(libraryStrings.RandString(32))
	ed, err := NewED(passphrase, salt, 0, 0, 46)
	require.NoError(t, err)
	// require.Equal(t, ed.iterations, iterations)
	// require.Equal(t, ed.keyLength, keyLength)
	require.Equal(t, ed.nonceLength, 46)
}

func TestEncryptor(t *testing.T) {
	salt := []byte(libraryStrings.RandString(16))
	data := []byte(libraryStrings.RandString(666))
	passphrase := []byte(libraryStrings.RandString(32))
	ed, err := NewED(passphrase, salt, 0, 0, 8)
	require.NoError(t, err)
	encrypted, err := ed.EncryptAES(data)
	require.NoError(t, err)
	decrypted, err := ed.DecryptAES(encrypted)
	require.NoError(t, err)
	require.Equal(t, data, decrypted)
}

func BenchmarkEncryptor(b *testing.B) {
	salt := []byte(libraryStrings.RandString(16))
	data := []byte(libraryStrings.RandString(666))
	passphrase := []byte(libraryStrings.RandString(32))
	ed, err := NewED(passphrase, salt, 0, 0, 8)
	require.NoError(b, err)
	for b.Loop() {
		encrypted, _ := ed.EncryptAES(data)
		_, _ = ed.DecryptAES(encrypted)

	}
}
