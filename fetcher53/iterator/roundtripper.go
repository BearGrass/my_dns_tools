package iterator

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"gitlab.alibaba-inc.com/fengjin.hf/cement/buffer"
	"gitlab.alibaba-inc.com/fengjin.hf/g53"
	dnsutil "gitlab.alibaba-inc.com/fengjin.hf/g53/util"
)

var ErrTooManyOutgoingQuery = errors.New("too many outgoing query")

const (
	QueryBufSize                 = 512
	MessageBufSize               = 1024
	DefaultMaxOutgoingQueryCount = 40960
)

type RoundTripper interface {
	Query(target Host, zone *g53.Name, req *g53.Message) (*g53.Message, ResponseCategory, error)
}

var _ RoundTripper = &DNSTransport{}

type DNSTransport struct {
	selector    HostSelector
	timeout     time.Duration
	renderPool  *sync.Pool
	querySource *net.UDPAddr
}

func NewDNSTransport(selector HostSelector, timeout time.Duration, maxOutgingQueryCount int) DNSTransport {
	if maxOutgingQueryCount <= 0 {
		maxOutgingQueryCount = DefaultMaxOutgoingQueryCount
	}

	renderPool := &sync.Pool{
		New: func() interface{} {
			return g53.NewMsgRender(QueryBufSize)
		},
	}

	querySource, _ := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	return DNSTransport{
		selector:    selector,
		timeout:     timeout,
		querySource: querySource,
		renderPool:  renderPool,
	}
}

//todo:
//- aggregate query to same host and with same question
//- add limitation about how many concurrent outgoing query
func (t DNSTransport) Query(target Host, zone *g53.Name, req *g53.Message) (*g53.Message, ResponseCategory, error) {
	builder := g53.NewRequestBuilder(&req.Question.Name, req.Question.Type)
	newReq := builder.SetId(dnsutil.GenMessageId()).SetHeaderFlag(g53.FLAG_RD, false).Done()
	resp, err := t.doQuery(target, newReq)
	if err == nil {
		question := req.Question
		category, err := SanitizeClassifyResponse(zone, &question.Name, question.Type, resp)
		return resp, category, err
	} else {
		return nil, ServerFail, err
	}
}

func (t DNSTransport) doQuery(target Host, req *g53.Message) (*g53.Message, error) {
	resp, err := t.doQueryUseUDP(target, req)
	if err != nil {
		return nil, err
	}

	if resp.Header.GetFlag(g53.FLAG_TC) {
		return t.doQueryUseTCP(target, req)
	} else {
		return resp, nil
	}
}

func (t DNSTransport) doQueryUseUDP(target Host, req *g53.Message) (*g53.Message, error) {
	conn, err := net.ListenUDP("udp", t.querySource)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	render := t.renderPool.Get().(*g53.MsgRender)
	req.Rend(render)
	defer func() {
		render.Clear()
		t.renderPool.Put(render)
	}()

	conn.SetWriteDeadline(time.Now().Add(t.timeout))
	conn.WriteTo(render.Data(), &net.UDPAddr{
		IP:   net.IP(target),
		Port: 53,
	})
	buf := make([]byte, MessageBufSize)
	sendTime := time.Now()
	conn.SetReadDeadline(time.Now().Add(t.timeout))
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.selector.SetTimeout(target, t.timeout)
		return nil, err
	}
	resp, err := g53.MessageFromWire(buffer.NewInputBuffer(buf[:n]))
	if err != nil {
		t.selector.SetTimeout(target, t.timeout)
		return nil, err
	}

	t.selector.SetRTT(target, time.Now().Sub(sendTime))
	if resp.Header.Id != req.Header.Id {
		return nil, fmt.Errorf("message id mismatch")
	} else {
		return resp, nil
	}
}

func (t DNSTransport) doQueryUseTCP(target Host, req *g53.Message) (*g53.Message, error) {
	render := t.renderPool.Get().(*g53.MsgRender)
	req.Rend(render)
	defer func() {
		render.Clear()
		t.renderPool.Put(render)
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:53", target.String()), t.timeout)
	if err != nil {
		return nil, err
	}

	conn.SetWriteDeadline(time.Now().Add(t.timeout))
	size := uint16(len(render.Data()))
	if err := binary.Write(conn, binary.BigEndian, &size); err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(t.timeout))
	if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(t.timeout))
	buf := make([]byte, size)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	resp, err := g53.MessageFromWire(buffer.NewInputBuffer(buf))
	if err == nil {
		return resp, nil
	} else {
		return nil, err
	}
}
