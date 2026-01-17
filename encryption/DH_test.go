package libraryEncryption_test

import (
	"testing"
	"time"

	libraryEncryption "github.com/pperminov/library/encryption"
	libraryTesting "github.com/pperminov/library/testing"
	"github.com/stretchr/testify/require"
)

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
	require.Len(t, sendKey1, 32)
	require.Len(t, rcvKey1, 32)
	require.NotEqual(t, sendKey1, rcvKey1)
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

func TestGetECDHKeysFromConnectionMultiple(t *testing.T) {
	for i := 0; i < 3; i++ {
		clientConn, serverConn := libraryTesting.NewLinkedMockConnections()

		var sendKey1, rcvKey1, sendKey2, rcvKey2 []byte
		var clientErr, serverErr error

		done := make(chan struct{}, 2)

		go func() {
			sendKey1, rcvKey1, clientErr = libraryEncryption.GetECDHKeysFromConnectionWithKeyDerivation(clientConn)
			done <- struct{}{}
		}()

		go func() {
			sendKey2, rcvKey2, serverErr = libraryEncryption.GetECDHKeysFromConnectionWithKeyDerivation(serverConn)
			done <- struct{}{}
		}()

		for j := 0; j < 2; j++ {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				_ = clientConn.Close()
				_ = serverConn.Close()
				t.Fatal("timeout waiting for key exchange")
			}
		}

		require.NoError(t, clientErr)
		require.NoError(t, serverErr)

		require.Equal(t, sendKey1, rcvKey2)
		require.Equal(t, sendKey2, rcvKey1)
		require.Len(t, sendKey1, 32)
		require.Len(t, rcvKey1, 32)
		require.NotEqual(t, sendKey1, rcvKey1)
	}
}
