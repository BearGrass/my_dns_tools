package iterator

import (
	"time"

	"gitlab.alibaba-inc.com/fengjin.hf/g53"
	"go.uber.org/zap"

	msgcache "gitlab.alibaba-inc.com/fengjin.hf/fetcher53/cache"
	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/logger"
	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/server"
)

const (
	SelectorCacheSize      = 10240
	UDPConnPoolSize        = 1024
	OneRoundTimeout        = 3 * time.Second
	IteratorTimeout        = 12 * time.Second
	MaxCNAMERedirectCount  = 8
	MaxDependentQueryCount = 4
	MaxReferralFollow      = 10
	MaxErrorRetryCount     = 5
)

type Iterator struct {
	cache        *msgcache.Cache
	rootHint     RootHint
	hostSelector HostSelector
	forwarder    *ForwardManager
	roundTripper RoundTripper
}

func NewIterator(cache *msgcache.Cache, forwarder *ForwardManager, maxOutgoingQueryCount int) (*Iterator, error) {
	selector := NewRTTBasedHostSelector(SelectorCacheSize)
	return newIterator(cache,
		NewRootHint(RootServers, RootGlues),
		selector,
		forwarder,
		NewDNSTransport(selector, OneRoundTimeout, maxOutgoingQueryCount)), nil
}

func newIterator(cache *msgcache.Cache,
	rootHint RootHint,
	selector HostSelector,
	forwarder *ForwardManager,
	roundTripper RoundTripper) *Iterator {
	return &Iterator{
		cache:        cache,
		rootHint:     rootHint,
		hostSelector: selector,
		forwarder:    forwarder,
		roundTripper: roundTripper,
	}
}

func (i *Iterator) Resolve(ctx *server.QueryContext) (*g53.Message, error) {
	event := NewEvent(ctx, &ctx.Request, InitQuery, Finished)
	for {
		if ctx.TraceQuery {
			logger.GetLogger().Info("handle event",
				zap.String("state", event.CurrentState().String()),
				zap.String("question", event.Request().Question.String()))
		}

		switch event.CurrentState() {
		case InitQuery:
			event = i.processInitQuery(event)
		case QueryTarget:
			event = i.processQueryTarget(event)
		case QueryResponse:
			event = i.processQueryResponse(event)
		case PrimeResponse:
			event = i.processPrimeResponse(event)
		case TargetResponse:
			event = i.processTargetResponse(event)
		case Finished:
			resp := i.processFinished(event)
			ReleaseEvent(event)
			return resp, nil
		default:
			panic("unreachable branche")
		}
	}
}

func (i *Iterator) processInitQuery(event *Event) *Event {
	if i.searchCache(event) {
		return event
	}

	if i.findDelegationPoint(event) {
		return event
	}

	return i.primeRoot(event)
}

func (i *Iterator) errorResponse(event *Event, rcode g53.Rcode) {
	resp := g53.NewResponseBuilder(event.Request()).
		SetRcode(rcode).
		Done()
	event.SetResponse(resp, ServerFail)
	event.SetNextState(event.FinalState())
}

func (i *Iterator) searchCache(event *Event) bool {
	req := event.Request()
	if resp := i.cache.Get(req); resp != nil {
		category := classifyCachedResponse(resp)
		event.SetResponse(resp, category)
		event.SetNextState(event.FinalState())
		event.CacheHit = true
		return true
	}

	resp, err := i.cache.GetCNameResponse(event.Request())
	if err != nil {
		if event.ctx.TraceQuery {
			logger.GetLogger().Warn("get cname response get error", zap.Error(err))
		}
		i.errorResponse(event, g53.R_SERVFAIL)
		return true
	} else if resp != nil {
		event.SetResponse(resp, CName)
		event.SetNextState(QueryResponse)
		return true
	} else {
		return false
	}
}

func (i *Iterator) findDelegationPoint(event *Event) bool {
	qname := &event.Request().Question.Name
	dp := i.forwarder.GetDelegationPoint(qname)
	if dp == nil {
		dp = NewFromCache(qname, i.cache)
	}

	if dp != nil {
		event.SetDelegationPoint(dp)
		event.SetNextState(QueryTarget)
		return true
	} else {
		return false
	}
}

func (i *Iterator) primeRoot(event *Event) *Event {
	req := g53.NewRequestBuilder(g53.Root, g53.RR_NS).Done()
	subEvent := NewEvent(event.ctx, req, QueryTarget, PrimeResponse)
	subEvent.SetDelegationPoint(i.rootHint.GetDelegationPoint())
	subEvent.SetBaseEvent(event)
	return subEvent
}

func (i *Iterator) processQueryTarget(event *Event) *Event {
	dp := event.GetDelegationPoint()
	host := dp.GetTarget(i.hostSelector)
	if host == nil {
		if event.Depth()+1 > MaxDependentQueryCount {
			if event.ctx.TraceQuery {
				logger.GetLogger().Warn("event depth execeed limit",
					zap.String("question", event.Request().Question.String()))
			}
			i.errorResponse(event, g53.R_SERVFAIL)
			return event
		}

		missingServer := dp.GetMissingServer()
		if missingServer == nil {
			if event.ctx.TraceQuery {
				logger.GetLogger().Warn("delegation point has no available host",
					zap.String("dp", dp.String()))
			}
			i.errorResponse(event, g53.R_SERVFAIL)
			return event
		}

		req := g53.NewRequestBuilder(missingServer, g53.RR_A).Done()
		subEvent := NewEvent(event.ctx, req, InitQuery, TargetResponse)
		subEvent.SetBaseEvent(event)
		subEvent.allowCName = false
		return subEvent
	}

	resp, category, err := i.roundTripper.Query(host, dp.Zone(), event.Request())
	if err != nil {
		if event.ctx.TraceQuery {
			logger.GetLogger().Warn("query failed",
				zap.String("zone", dp.Zone().String(false)),
				zap.String("host", host.String()),
				zap.String("question", event.Request().Question.String()),
				zap.Error(err))
		}

		if time.Since(event.StartTime) > IteratorTimeout {
			i.errorResponse(event, g53.R_SERVFAIL)
		}
		event.ErrCount += 1
		if event.ErrCount > MaxErrorRetryCount {
			if event.ctx.TraceQuery {
				logger.GetLogger().Warn("err count execeed limit", zap.Int("error count", int(event.ErrCount)))
			}
			i.errorResponse(event, g53.R_SERVFAIL)
		}
		return event
	}

	//fmt.Printf("get from %s[%s] response:%s\n", dp.Zone().String(false), host.String(), resp.String())

	switch category {
	case Answer:
		i.cache.Add(resp)
	case NXDomain, NXRRset:
		if IsNegativeAnswerCacheable(resp) {
			i.cache.Add(resp)
		}
	case CName, CNameAnswer, Referral:
		i.cache.AddRRset(resp)
	case ServerFail:
		dp.MarkHostLame(host)
		return event
	default:
		panic("unknown category")
	}
	event.SetResponse(resp, category)
	event.SetNextState(QueryResponse)
	return event
}

func (i *Iterator) processQueryResponse(event *Event) *Event {
	resp, category := event.Response()
	switch category {
	case Answer, NXDomain, NXRRset:
		event.SetNextState(event.FinalState())
	case CNameAnswer:
		if event.allowCName {
			event.SetNextState(event.FinalState())
		} else {
			i.errorResponse(event, g53.R_SERVFAIL)
		}
	case Referral:
		dp := NewFromReferralResponse(resp)
		event.ReferralCount += 1
		if event.ReferralCount > MaxReferralFollow {
			if event.ctx.TraceQuery {
				logger.GetLogger().Warn("ns query execeed limit",
					zap.Int("referral count", int(event.ReferralCount)))
				i.errorResponse(event, g53.R_SERVFAIL)
			}
			return event
		}
		event.SetDelegationPoint(dp)
		event.SetNextState(QueryTarget)
	case CName:
		if event.allowCName {
			answers := resp.GetSection(g53.AnswerSection)
			next := answers[len(answers)-1].Rdatas[0].(*g53.CName).Name
			qtype := event.Request().Question.Type
			event.AddPrependRRset(answers)
			event.SetCurrentRequest(g53.NewRequestBuilder(next, qtype).Done())
			event.SetNextState(InitQuery)
			event.QueryRestartCount += 1
			if event.QueryRestartCount > MaxCNAMERedirectCount {
				if event.ctx.TraceQuery {
					logger.GetLogger().Warn("event cname redirect execeed limit",
						zap.String("question", event.Request().Question.String()))
				}
				i.errorResponse(event, g53.R_SERVFAIL)
			}
		} else {
			i.errorResponse(event, g53.R_SERVFAIL)
		}
	default:
		event.SetNextState(QueryTarget)
	}
	return event
}

func (i *Iterator) processPrimeResponse(event *Event) *Event {
	base := event.BaseEvent()
	resp, category := event.Response()
	if category == Answer {
		dp := NewFromNSRRset(resp.GetSection(g53.AnswerSection)[0], resp.GetSection(g53.AdditionalSection))
		base.SetDelegationPoint(dp)
		base.SetNextState(QueryTarget)
	} else {
		if event.ctx.TraceQuery {
			logger.GetLogger().Warn("prime failed",
				zap.String("prime answer category", category.String()))
		}
		i.errorResponse(base, g53.R_SERVFAIL)
	}
	ReleaseEvent(event)
	return base
}

func (i *Iterator) processTargetResponse(event *Event) *Event {
	base := event.BaseEvent()
	resp, category := event.Response()
	if category == Answer {
		answers := resp.GetSection(g53.AnswerSection)
		lastRRset := answers[len(answers)-1]
		if lastRRset.Type == g53.RR_A {
			qname := &event.OriginalRequest().Question.Name
			if !lastRRset.Name.Equals(qname) {
				lastRRset.Name = qname.Clone()
			}
			base.GetDelegationPoint().AddGlue(lastRRset)
		}
	} else {
		qname := &event.OriginalRequest().Question.Name
		base.GetDelegationPoint().MarkServerProbed(qname)
	}
	ReleaseEvent(event)
	return base
}

func (i *Iterator) processFinished(event *Event) *g53.Message {
	hasCNameRedirect := event.QueryRestartCount > 0
	resp := event.GenerateResponse()

	//only cache synthetic answer
	if hasCNameRedirect && (resp.Header.Rcode == g53.R_NOERROR && resp.Header.ANCount > 0) {
		i.cache.Add(resp)
	}
	return resp
}
