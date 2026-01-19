package util

import (
	"net"
	"time"
)

var (
	port int
)

type Client struct {
	req    []byte
	addr   *net.UDPAddr
	answer []byte
}

type TimeoutConn struct {
	*net.UDPConn
	timeout time.Duration
}

func NewClientTimeoutConn(addr string, timeout time.Duration) (*TimeoutConn, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return nil, err
	}

	return &TimeoutConn{
		UDPConn: conn,
		timeout: timeout,
	}, nil
}

func NewServerTimeConn(addr string, timeout time.Duration) (*TimeoutConn, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		return nil, err
	}

	return &TimeoutConn{
		UDPConn: conn,
		timeout: timeout,
	}, nil
}

func (c *TimeoutConn) Write(data []byte) (int, error) {
	c.UDPConn.SetWriteDeadline(time.Now().Add(c.timeout))
	return c.UDPConn.Write(data)
}

func (c *TimeoutConn) ReadFromUDP(data []byte) (int, *net.UDPAddr, error) {
	c.UDPConn.SetReadDeadline(time.Now().Add(c.timeout))
	return c.UDPConn.ReadFromUDP(data)
}

func (c *TimeoutConn) WriteTo(data []byte, addr *net.UDPAddr) (int, error) {
	c.UDPConn.SetWriteDeadline(time.Now().Add(c.timeout))
	return c.UDPConn.WriteTo(data, addr)
}
