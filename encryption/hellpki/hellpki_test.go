package hellpki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/pperminov/library/encryption/hellpki"
	libraryTesting "github.com/pperminov/library/testing"
	"github.com/stretchr/testify/require"
)

func TestHellPKI(t *testing.T) {
	conn1, conn2 := libraryTesting.NewLinkedMockConnections()

	priv1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	priv2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	c1, err := hellpki.MakeAHellCirclePKI(conn1, hellpki.Config{
		LocalPrivateKey: priv1,
		RemotePublicKey: &priv2.PublicKey,
		SignMessages:    true,
		VerifyMessages:  true,
		Context:         []byte("test"),
	})
	require.NoError(t, err)

	c2, err := hellpki.MakeAHellCirclePKI(conn2, hellpki.Config{
		LocalPrivateKey: priv2,
		RemotePublicKey: &priv1.PublicKey,
		SignMessages:    true,
		VerifyMessages:  true,
		Context:         []byte("test"),
	})
	require.NoError(t, err)

	msg1 := []byte("hello from one")
	_, err = c1.Write(msg1)
	require.NoError(t, err)
	buf := make([]byte, 1024)
	n, err := c2.Read(buf)
	require.NoError(t, err)
	require.Equal(t, msg1, buf[:n])

	msg2 := []byte("hello from two")
	_, err = c2.Write(msg2)
	require.NoError(t, err)
	n, err = c1.Read(buf)
	require.NoError(t, err)
	require.Equal(t, msg2, buf[:n])
}
