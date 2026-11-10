package libraryNetwork

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"
)

type UDPDiscovery struct {
	conn            *net.UDPConn
	port            int
	bufferSize      int
	includeLoopback bool
	broadcastAddrs  []*net.UDPAddr
}

type UDPDiscoveryOption func(*UDPDiscovery)

func WithDiscoveryBufferSize(size int) UDPDiscoveryOption {
	return func(d *UDPDiscovery) {
		if size > 0 {
			d.bufferSize = size
		}
	}
}

func WithDiscoveryLoopback(include bool) UDPDiscoveryOption {
	return func(d *UDPDiscovery) {
		d.includeLoopback = include
	}
}

func WithDiscoveryBroadcastAddrs(addrs []*net.UDPAddr) UDPDiscoveryOption {
	return func(d *UDPDiscovery) {
		d.broadcastAddrs = addrs
	}
}

func NewUDPDiscovery(port int, opts ...UDPDiscoveryOption) (*UDPDiscovery, error) {
	if port <= 0 {
		return nil, fmt.Errorf("udp discovery port must be > 0")
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		return nil, err
	}
	if err := enableUDPBroadcast(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	discovery := &UDPDiscovery{
		conn:       conn,
		port:       port,
		bufferSize: 2048,
	}
	for _, opt := range opts {
		opt(discovery)
	}
	return discovery, nil
}

func (d *UDPDiscovery) Close() error {
	return d.conn.Close()
}

func (d *UDPDiscovery) Broadcast(payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	addrs := d.broadcastAddrs
	if len(addrs) == 0 {
		var err error
		addrs, err = BroadcastUDPAddrs(d.port, d.includeLoopback)
		if err != nil {
			return err
		}
		if len(addrs) == 0 {
			addrs = []*net.UDPAddr{{IP: net.IPv4bcast, Port: d.port}}
		}
	}
	for _, addr := range addrs {
		if _, err := d.conn.WriteToUDP(payload, addr); err != nil {
			return err
		}
	}
	return nil
}

func (d *UDPDiscovery) Receive() ([]byte, *net.UDPAddr, error) {
	buffer := make([]byte, d.bufferSize)
	n, addr, err := d.conn.ReadFromUDP(buffer)
	if err != nil {
		return nil, nil, err
	}
	payload := make([]byte, n)
	copy(payload, buffer[:n])
	return payload, addr, nil
}

func (d *UDPDiscovery) Listen(ctx context.Context, handler func([]byte, *net.UDPAddr)) error {
	if handler == nil {
		return fmt.Errorf("udp discovery handler is nil")
	}
	buffer := make([]byte, d.bufferSize)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_ = d.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, addr, err := d.conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}
		payload := make([]byte, n)
		copy(payload, buffer[:n])
		handler(payload, addr)
	}
}

func BroadcastUDPAddrs(port int, includeLoopback bool) ([]*net.UDPAddr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var addrs []*net.UDPAddr
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagBroadcast == 0 {
			continue
		}
		if !includeLoopback && iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range ifaceAddrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP == nil || ipNet.Mask == nil {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil {
				continue
			}
			if !includeLoopback && ip4.IsLoopback() {
				continue
			}
			broadcast := broadcastAddr(ip4, ipNet.Mask)
			if broadcast == nil {
				continue
			}
			key := broadcast.String()
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			addrs = append(addrs, &net.UDPAddr{IP: broadcast, Port: port})
		}
	}
	return addrs, nil
}

func broadcastAddr(ip net.IP, mask net.IPMask) net.IP {
	if len(mask) != net.IPv4len {
		return nil
	}
	broadcast := make(net.IP, net.IPv4len)
	for i := 0; i < net.IPv4len; i++ {
		broadcast[i] = ip[i] | ^mask[i]
	}
	return broadcast
}

func enableUDPBroadcast(conn *net.UDPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	if err := rawConn.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	}); err != nil {
		return err
	}
	return sockErr
}
