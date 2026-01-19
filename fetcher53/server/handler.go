package server

import (
	"net"
	"sync"

	"gitlab.alibaba-inc.com/fengjin.hf/cement/buffer"
	"gitlab.alibaba-inc.com/fengjin.hf/g53"
)

const (
	DefaultEdnsBufferSize = 1232
)

var defaultEdns = &g53.EDNS{
	UdpSize: DefaultEdnsBufferSize,
}

type Handler interface {
	Resolve(*QueryContext) (*g53.Message, error)
}

type QueryContext struct {
	Request    g53.Message
	UseTCP     bool
	SrcAddr    net.Addr
	DestAddr   net.Addr
	TraceQuery bool

	conn   net.Conn
	buf    []byte
	buffer *buffer.InputBuffer
	render *g53.MsgRender
}

var queryCtxPool = &sync.Pool{
	New: func() interface{} {
		return &QueryContext{
			buf:    make([]byte, MaxQueryLen),
			buffer: buffer.NewInputBuffer(nil),
			render: g53.NewMsgRender(DefaultEdnsBufferSize),
		}
	},
}

func getQueryContext(useTCP bool) *QueryContext {
	ctx := queryCtxPool.Get().(*QueryContext)
	ctx.UseTCP = useTCP
	return ctx
}

func releaseQueryContext(ctx *QueryContext) {
	ctx.render.Clear()
	ctx.Request.Clear()
	ctx.buf = ctx.buf[:MaxQueryLen]
	queryCtxPool.Put(ctx)
}

func (ctx *QueryContext) parseQuery() bool {
	ctx.buffer.SetData(ctx.buf)
	err := ctx.Request.FromWire(ctx.buffer)
	if err == nil && ctx.Request.Header.Opcode == g53.OP_QUERY {
		edns, _ := ctx.Request.GetEdns()
		ctx.TraceQuery = edns != nil && edns.UdpSize == 1
		return true
	} else {
		return false
	}
}

func (ctx *QueryContext) runHandler(handler Handler, transport *Transport) bool {
	resp, err := handler.Resolve(ctx)
	if err == nil && resp != nil {
		g53.NewMsgBuilder(resp).SetEdns(defaultEdns).Done()
		resp.Rend(ctx.render)
		if ctx.UseTCP {
			transport.SendTCPResponse(ctx.conn, ctx.render.Data())
		} else {
			transport.SendUDPResponse(ctx.SrcAddr, ctx.conn, ctx.render.Data())
		}
		return true
	} else {
		return false
	}
}
