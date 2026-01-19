package server

import (
	"fmt"
	"net"
	"sync"

	"go.uber.org/zap"

	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/logger"
	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/metrics"
)

const (
	DefaultTCPQuickHandlerCount = 16
	DefaultTCPSlowHandlerCount  = 32
	DefaultUDPQuickHandlerCount = 1024
)

type message struct {
	usingTCP bool
	addr     net.Addr
	destAddr net.Addr
	conn     net.Conn
	buf      []byte
}

type Server struct {
	transport    *Transport
	quickHandler Handler
	slowHandler  Handler

	handlerCount int
	stopChan     chan struct{}
	wg           sync.WaitGroup
	metric       *metrics.Metrics
}

func NewServer(addrs []string, quickHandler, slowHandler Handler, handlerCount int, metric *metrics.Metrics) (*Server, error) {
	transport, err := newTransport(addrs)
	if err != nil {
		return nil, err
	}

	s := &Server{
		transport:    transport,
		quickHandler: quickHandler,
		slowHandler:  slowHandler,
		handlerCount: handlerCount,
		stopChan:     make(chan struct{}),
		metric:       metric,
	}

	return s, nil
}

func (s *Server) Start() {
	tcpMsgCh, udpMsgChs := s.transport.run()

	tcpForwardCh := make(chan *QueryContext, DefaultTCPSlowHandlerCount)
	s.startQuickHandler(DefaultTCPQuickHandlerCount, tcpMsgCh, tcpForwardCh)
	s.startSlowHandler(DefaultTCPSlowHandlerCount, tcpForwardCh)

	udpForwardCh := make(chan *QueryContext, s.handlerCount*2)
	for _, ch := range udpMsgChs {
		s.startQuickHandler(DefaultUDPQuickHandlerCount, ch, udpForwardCh)
	}
	s.startSlowHandler(s.handlerCount, udpForwardCh)
}

func (s *Server) ExportIPs() []string {
	return s.transport.exportIPs
}

func (s *Server) Stop() {
	s.transport.Close()
	close(s.stopChan)
	s.wg.Wait()
}

func (s *Server) startQuickHandler(handlerCount int, msgCh <-chan *QueryContext, forwardCh chan<- *QueryContext) {
	for i := 0; i < handlerCount; i++ {
		s.wg.Add(1)
		go func() {
			defer func() {
				if p := recover(); p != nil {
					logger.GetLogger().Fatal("query handle thread creashed",
						zap.String("recover", fmt.Sprintf("%v", p)))

					//s.startQuickHandler(1, msgCh, forwardCh)
				}
				s.wg.Done()
			}()

			for {
				select {
				case <-s.stopChan:
					return
				case ctx := <-msgCh:
					s.metric.RecordQuery()
					if !ctx.parseQuery() {
						releaseQueryContext(ctx)
						continue
					}

					if !ctx.runHandler(s.quickHandler, s.transport) {
						select {
						case forwardCh <- ctx:
							if ctx.TraceQuery {
								logger.GetLogger().Info("query forward to resolver", zap.String("question", ctx.Request.Question.String()))
							}
						default:
							if ctx.TraceQuery {
								logger.GetLogger().Warn("slow resolver is too busy, drop pkt")
							}
							releaseQueryContext(ctx)
						}
					} else {
						if ctx.TraceQuery {
							logger.GetLogger().Info("query hit cache", zap.String("question", ctx.Request.Question.String()))
						}
						releaseQueryContext(ctx)
					}
				}
			}
		}()
	}
}

func (s *Server) startSlowHandler(handlerCount int, msgCh <-chan *QueryContext) {
	for i := 0; i < handlerCount; i++ {
		s.wg.Add(1)
		go func() {
			defer func() {
				if p := recover(); p != nil {
					logger.GetLogger().Fatal("query handle thread creashed",
						zap.String("recover", fmt.Sprintf("%v", p)))
					//s.startSlowHandler(1, msgCh)
				}
				s.wg.Done()
			}()

			for {
				select {
				case <-s.stopChan:
					return
				case ctx := <-msgCh:
					ctx.runHandler(s.slowHandler, s.transport)
					releaseQueryContext(ctx)
				}
			}
		}()
	}
}
