package server

import (
	"fmt"
	"net"
	"runtime"
	"sync/atomic"

	"github.com/libp2p/go-reuseport"
	"go.uber.org/zap"

	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/logger"
	"gitlab.alibaba-inc.com/fengjin.hf/g53/util"
)

const (
	MaxConcurrentTCPConn = 512
	MaxQueryLen          = 512
	UdpReceiveBuf        = 1024 * MaxQueryLen
	MsgChBufLen          = 1024
)

type Transport struct {
	exportIPs []string

	udpConns     []net.PacketConn
	tcpListeners []net.Listener
	tcpConnCount int32
}

func newTransport(addrs []string) (*Transport, error) {
	t := &Transport{}
	cpuCount := runtime.NumCPU()
	logger.GetLogger().Info("start handler",
		zap.String("message queue count for each addr", fmt.Sprintf("%v", cpuCount)))

	if err := t.openUDP(addrs, cpuCount); err != nil {
		t.Close()
		return nil, err
	}

	if err := t.openTCP(addrs, cpuCount); err != nil {
		t.Close()
		return nil, err
	} else {
		return t, nil
	}
}

func (t *Transport) openUDP(addrs []string, cpuCount int) error {
	udpConns := make([]net.PacketConn, 0, len(addrs)*cpuCount)
	for _, addr := range addrs {
		for i := 0; i < cpuCount; i++ {
			conn, err := reuseport.ListenPacket("udp", addr)
			if err != nil {
				return err
			}
			udpConns = append(udpConns, conn)
		}
		logger.GetLogger().Info("listen on udp", zap.String("addr", addr))
	}
	t.udpConns = udpConns
	return nil
}

func (t *Transport) openTCP(addrs []string, cpuCount int) error {
	listeners := make([]net.Listener, 0, len(addrs)*cpuCount)
	for _, addr := range addrs {
		for i := 0; i < cpuCount; i++ {
			li, err := reuseport.Listen("tcp", addr)
			if err != nil {
				return err
			}
			listeners = append(listeners, li)
		}
		logger.GetLogger().Info("listen on tcp", zap.String("addr", addr))
	}
	t.tcpListeners = listeners
	return nil
}

func (t *Transport) run() (<-chan *QueryContext, []<-chan *QueryContext) {
	return t.runTCP(), t.runUDP()
}

func (t *Transport) runTCP() <-chan *QueryContext {
	msgCh := make(chan *QueryContext, MsgChBufLen)
	for _, l := range t.tcpListeners {
		go func(listener net.Listener) {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}

				if atomic.LoadInt32(&t.tcpConnCount) < MaxConcurrentTCPConn {
					atomic.AddInt32(&t.tcpConnCount, 1)
					go t.handleTCPConn(conn, msgCh)
				} else {
					conn.Close()
				}
			}
		}(l)
	}
	return msgCh
}

func (t *Transport) handleTCPConn(conn net.Conn, msgCh chan *QueryContext) {
	ctx := getQueryContext(true)
	if n, err := util.TCPRead(conn.(*net.TCPConn), ctx.buf); err == nil {
		ctx.buf = ctx.buf[:n]
		ctx.SrcAddr = conn.RemoteAddr()
		ctx.DestAddr = conn.LocalAddr()
		ctx.conn = conn
		msgCh <- ctx
	} else {
		t.releaseConn(conn)
		releaseQueryContext(ctx)
	}
}

func (t *Transport) releaseConn(conn net.Conn) {
	conn.Close()
	atomic.AddInt32(&t.tcpConnCount, -1)
}

func (t *Transport) runUDP() []<-chan *QueryContext {
	chs := make([]<-chan *QueryContext, 0, len(t.udpConns))
	for _, conn := range t.udpConns {
		ch := make(chan *QueryContext, MsgChBufLen)
		chs = append(chs, ch)
		go func(conn net.PacketConn) {
			for {
				ctx := getQueryContext(false)
				n, addr, err := conn.ReadFrom(ctx.buf)
				if err == nil && n > 0 && n < MaxQueryLen {
					ctx.SrcAddr = addr
					ctx.DestAddr = conn.LocalAddr()
					ctx.conn = conn.(*net.UDPConn)
					ctx.buf = ctx.buf[0:n]
					select {
					case ch <- ctx:
					default:
						logger.GetLogger().Warn("resolver is too busy, drop pkt")
						releaseQueryContext(ctx)
					}
				} else {
					releaseQueryContext(ctx)
				}
			}
		}(conn)
	}

	return chs
}

func (t *Transport) Close() {
	for _, conn := range t.udpConns {
		conn.Close()
	}

	for _, l := range t.tcpListeners {
		l.Close()
	}
}

func (t *Transport) SendUDPResponse(target net.Addr, conn net.Conn, response []byte) {
	conn.(*net.UDPConn).WriteTo(response, target)
}

func (t *Transport) SendTCPResponse(conn net.Conn, response []byte) {
	util.TCPWrite(response, conn.(*net.TCPConn))
	t.releaseConn(conn.(*net.TCPConn))
}
