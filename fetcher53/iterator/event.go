package iterator

import (
	"sync"
	"time"

	"gitlab.alibaba-inc.com/fengjin.hf/g53"

	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/server"
)

type QueryState uint8

const (
	InitQuery      QueryState = 0
	QueryTarget    QueryState = 1
	QueryResponse  QueryState = 2
	PrimeResponse  QueryState = 3
	TargetResponse QueryState = 4
	Finished       QueryState = 5
)

func (s QueryState) String() string {
	switch s {
	case InitQuery:
		return "init"
	case QueryTarget:
		return "queryTarget"
	case QueryResponse:
		return "queryResponse"
	case PrimeResponse:
		return "primeResponse"
	case TargetResponse:
		return "targetResponse"
	case Finished:
		return "finished"
	default:
		panic("invalid state")
	}
}

type Event struct {
	baseEvent *Event
	ctx       *server.QueryContext

	orignalRequest   *g53.Message
	currentRequest   *g53.Message
	response         *g53.Message
	responseCategory ResponseCategory
	//some query doesn't allow cname like glue record
	allowCName      bool
	state           QueryState
	finalState      QueryState
	prependRRset    []*g53.RRset
	delegationPoint *DelegationPoint

	StartTime         time.Time
	CacheHit          bool
	ErrCount          uint8
	QueryRestartCount uint8
	ReferralCount     uint8
}

func (e *Event) init(ctx *server.QueryContext, req *g53.Message, initState, finalState QueryState) {
	e.ctx = ctx
	e.orignalRequest = req
	e.state = initState
	e.finalState = finalState
	e.StartTime = time.Now()
	e.allowCName = true
}

func (e *Event) clean() {
	e.baseEvent = nil
	e.orignalRequest = nil
	e.currentRequest = nil
	e.response = nil
	e.prependRRset = nil
	e.delegationPoint = nil
	e.CacheHit = false
	e.ErrCount = 0
	e.QueryRestartCount = 0
	e.ReferralCount = 0
}

func (e *Event) SetDelegationPoint(dp *DelegationPoint) {
	e.delegationPoint = dp
}

func (e *Event) GetDelegationPoint() *DelegationPoint {
	return e.delegationPoint
}

func (e *Event) CurrentState() QueryState {
	return e.state
}

func (e *Event) FinalState() QueryState {
	return e.finalState
}

func (e *Event) SetNextState(state QueryState) {
	e.state = state
}

func (e *Event) Depth() int {
	if e.baseEvent != nil {
		return e.baseEvent.Depth() + 1
	} else {
		return 0
	}
}

func (e *Event) Request() *g53.Message {
	if e.currentRequest != nil {
		return e.currentRequest
	} else {
		return e.orignalRequest
	}
}

func (e *Event) OriginalRequest() *g53.Message {
	return e.orignalRequest
}

func (e *Event) SetCurrentRequest(req *g53.Message) {
	e.currentRequest = req
}

func (e *Event) SetResponse(resp *g53.Message, category ResponseCategory) {
	e.response = resp
	e.responseCategory = category
}

func (e *Event) Response() (*g53.Message, ResponseCategory) {
	return e.response, e.responseCategory
}

func (e *Event) AddPrependRRset(rrsets []*g53.RRset) {
	e.prependRRset = append(e.prependRRset, rrsets...)
}

func (e *Event) SetBaseEvent(base *Event) {
	if e.baseEvent != nil {
		panic("event has multi base event")
	}
	e.baseEvent = base
}

func (e *Event) BaseEvent() *Event {
	return e.baseEvent
}

func (e *Event) GenerateResponse() *g53.Message {
	builder := g53.NewResponseBuilder(e.orignalRequest).
		SetRcode(e.response.Header.Rcode).
		SetHeaderFlag(g53.FLAG_RA, true).
		SetHeaderFlag(g53.FLAG_AA, false)
	switch e.response.Header.Rcode {
	case g53.R_NOERROR:
		for _, rrset := range e.prependRRset {
			builder.AddRRset(g53.AnswerSection, rrset)
		}
		for _, st := range []g53.SectionType{g53.AnswerSection, g53.AuthSection, g53.AdditionalSection} {
			for _, rrset := range e.response.GetSection(st) {
				builder.AddRRset(st, rrset)
			}
		}
	case g53.R_NXDOMAIN:
		//for cname target has nxdomain, previous cname answer should be
		//included in response
		for _, rrset := range e.prependRRset {
			builder.AddRRset(g53.AnswerSection, rrset)
		}
		for _, rrset := range e.response.GetSection(g53.AuthSection) {
			builder.AddRRset(g53.AuthSection, rrset)
		}
	}
	return builder.Done()
}

var eventPool = &sync.Pool{
	New: func() interface{} {
		return &Event{}
	},
}

func NewEvent(ctx *server.QueryContext, req *g53.Message, start, end QueryState) *Event {
	event := eventPool.Get().(*Event)
	event.init(ctx, req, start, end)
	return event
}

func ReleaseEvent(event *Event) {
	event.clean()
	eventPool.Put(event)
}
