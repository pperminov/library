package libraryEncryption

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeriveECDHKeysOrdering(t *testing.T) {
	sharedSecret := []byte("shared-secret-for-hkdf")
	pubA := []byte{0x01, 0x02, 0x03}
	pubB := []byte{0x04, 0x05, 0x06}

	sendA, recvA, err := deriveECDHKeys(sharedSecret, pubA, pubB)
	require.NoError(t, err)
	sendB, recvB, err := deriveECDHKeys(sharedSecret, pubB, pubA)
	require.NoError(t, err)

	require.Equal(t, sendA, recvB)
	require.Equal(t, recvA, sendB)
	require.NotEqual(t, sendA, recvA)
	require.Len(t, sendA, 32)
	require.Len(t, recvA, 32)
}
