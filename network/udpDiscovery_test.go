package libraryNetwork

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBroadcastAddr(t *testing.T) {
	ip := net.ParseIP("192.168.1.10").To4()
	mask := net.CIDRMask(24, 32)
	broadcast := broadcastAddr(ip, mask)
	require.Equal(t, net.ParseIP("192.168.1.255").To4(), broadcast)
	require.Nil(t, broadcastAddr(net.ParseIP("2001:db8::1"), net.CIDRMask(64, 128)))
}

func TestUDPDiscoveryReceive(t *testing.T) {
	port := freeUDPPort(t)
	discovery, err := NewUDPDiscovery(port, WithDiscoveryBufferSize(256), WithDiscoveryLoopback(true))
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = discovery.Close()
	})

	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = client.Close()
	})

	payload := []byte{0x10, 0x20, 0x30}
	_, err = client.Write(payload)
	require.NoError(t, err)

	data, addr, err := discovery.Receive()
	require.NoError(t, err)
	require.NotNil(t, addr)
	require.Equal(t, payload, data)
}

func TestUDPDiscoveryListen(t *testing.T) {
	port := freeUDPPort(t)
	discovery, err := NewUDPDiscovery(port, WithDiscoveryBufferSize(256), WithDiscoveryLoopback(true))
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = discovery.Close()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	received := make(chan []byte, 1)
	errChan := make(chan error, 1)
	go func() {
		errChan <- discovery.Listen(ctx, func(data []byte, addr *net.UDPAddr) {
			if addr == nil {
				return
			}
			received <- data
			cancel()
		})
	}()

	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = client.Close()
	})
	payload := []byte("payload")
	_, err = client.Write(payload)
	require.NoError(t, err)

	select {
	case data := <-received:
		require.True(t, bytes.Equal(payload, data))
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for discovery listener")
	}

	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for listener shutdown")
	}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	require.NoError(t, err)
	defer func() {
		_ = conn.Close()
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port
}
