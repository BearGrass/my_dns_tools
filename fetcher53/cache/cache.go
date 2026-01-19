package cache

import (
	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/server"
	"gitlab.alibaba-inc.com/fengjin.hf/g53"
)

const (
	RatioOfRRsetAndMessageCacheSize = 5
)

type Cache struct {
	positive *MessageCache
	negative *MessageCache
}

func NewCache(cap int) *Cache {
	rrsetCache := newRRsetCache(cap * RatioOfRRsetAndMessageCacheSize)
	return &Cache{
		positive: newMessageCache(cap, rrsetCache),
		negative: newMessageCache(cap, rrsetCache),
	}
}

func (c *Cache) Resolve(ctx *server.QueryContext) (*g53.Message, error) {
	return c.Get(&ctx.Request), nil
}

func (c *Cache) Get(req *g53.Message) *g53.Message {
	if resp := c.positive.Get(req); resp != nil {
		return resp
	} else if resp := c.negative.Get(req); resp != nil {
		return resp
	} else {
		return nil
	}
}

func (c *Cache) Len() int {
	return c.positive.Len() + c.negative.Len()
}

func (c *Cache) GetCNameResponse(req *g53.Message) (*g53.Message, error) {
	return c.positive.GetCNameResponse(req)
}

func (c *Cache) Add(msg *g53.Message) {
	if isNegativeResponse(msg) {
		c.positive.Add(msg)
	} else {
		c.negative.Add(msg)
	}
}

func (c *Cache) AddRRset(msg *g53.Message) {
	c.positive.AddRRset(msg)
}

func (c *Cache) Remove(name *g53.Name, typ g53.RRType) bool {
	return c.positive.Remove(name, typ) || c.negative.Remove(name, typ)
}

func (c *Cache) GetClosestNS(name *g53.Name) *g53.RRset {
	return c.positive.GetClosestNS(name)
}

func (c *Cache) GetRRset(name *g53.Name, typ g53.RRType) *g53.RRset {
	return c.positive.GetRRset(name, typ)
}

func isNegativeResponse(resp *g53.Message) bool {
	if resp.Header.ANCount == 0 {
		return true
	}

	answers := resp.GetSection(g53.AnswerSection)
	last := answers[len(answers)-1]
	return last.Type == resp.Question.Type
}
