package libraryEncryption_test

import (
	"testing"

	libraryEncryption "github.com/pperminov/library/encryption"
	libraryTesting "github.com/pperminov/library/testing"
	"github.com/stretchr/testify/require"
)

// TODO make multiple requests in a row
// TODO Failing with some reason. Need to investigate
// func TestGetDHSecretFromConnection(t *testing.T) {
// 	p, _ := new(big.Int).SetString("23", 10)
// 	g := big.NewInt(5)

// 	clientConn, serverConn := libraryTesting.NewLinkedMockConnections()

// 	var clientSecret, serverSecret []byte
// 	var clientErr, serverErr error

// 	done := make(chan struct{})

// 	go func() {
// 		clientSecret, clientErr = libraryEncryption.GetDHSecretFromConnection(clientConn, p, g)
// 		done <- struct{}{}
// 	}()

// 	go func() {
// 		serverSecret, serverErr = libraryEncryption.GetDHSecretFromConnection(serverConn, p, g)
// 		done <- struct{}{}
// 	}()

// 	<-done
// 	<-done

// 	require.NoError(t, clientErr)
// 	require.NoError(t, serverErr)

// 	require.Equal(t, clientSecret, serverSecret)
// }

func TestGetECDHSecretFromConnectionWithKeyDerivation(t *testing.T) {
	clientConn, serverConn := libraryTesting.NewLinkedMockConnections()

	var sendKey1, rcvKey1, sendKey2, rcvKey2 []byte
	var clientErr, serverErr error

	done := make(chan struct{})

	go func() {
		sendKey1, rcvKey1, clientErr = libraryEncryption.GetECDHKeysFromConnectionWithKeyDerivation(clientConn)
		done <- struct{}{}
	}()

	go func() {
		sendKey2, rcvKey2, serverErr = libraryEncryption.GetECDHKeysFromConnectionWithKeyDerivation(serverConn)
		done <- struct{}{}
	}()

	<-done
	<-done

	require.NoError(t, clientErr)
	require.NoError(t, serverErr)

	require.Equal(t, sendKey1, rcvKey2)
	require.Equal(t, sendKey2, rcvKey1)
}

func TestGetECDHSecretFromConnection(t *testing.T) {
	clientConn, serverConn := libraryTesting.NewLinkedMockConnections()

	var key1, key2 []byte
	var clientErr, serverErr error

	done := make(chan struct{})

	go func() {
		key1, clientErr = libraryEncryption.GetECDHKeysFromConnection(clientConn)
		done <- struct{}{}
	}()

	go func() {
		key2, serverErr = libraryEncryption.GetECDHKeysFromConnection(serverConn)
		done <- struct{}{}
	}()

	<-done
	<-done

	require.NoError(t, clientErr)
	require.NoError(t, serverErr)

	require.Equal(t, key1, key2)
}
