package cache

import (
	"container/list"
	"fmt"
	"sync"
	"time"

	"gitlab.alibaba-inc.com/fengjin.hf/g53"

	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/util"
)

const (
	MaxCNameChainDepth = 10
)

type RRsetHash struct {
	keyHash      uint64
	conflictHash uint64
}

type MessageEntry struct {
	keyHash         uint64
	conflictHash    uint64
	rcode           g53.Rcode
	answerCount     int //rrset count not rr count
	authorityCount  int
	additionalCount int
	rrsets          []RRsetHash
	expireTime      time.Time
}

func (e *MessageEntry) IsExpire() bool {
	return e.expireTime.Before(time.Now())
}

type MessageCache struct {
	cap        int
	data       map[uint64]*list.Element
	ll         *list.List
	lock       sync.Mutex
	rrsetCache *RRsetCache
}

func newMessageCache(cap int, rrsetCache *RRsetCache) *MessageCache {
	return &MessageCache{
		ll:         list.New(),
		data:       make(map[uint64]*list.Element),
		cap:        cap,
		rrsetCache: rrsetCache,
	}
}

func (c *MessageCache) Len() int {
	c.lock.Lock()
	defer c.lock.Unlock()

	return len(c.data)
}

func (c *MessageCache) Get(req *g53.Message) *g53.Message {
	keyHash, conflictHash := util.HashQuery(&req.Question.Name, req.Question.Type)
	c.lock.Lock()
	defer c.lock.Unlock()

	me, found := c.get(keyHash, conflictHash)
	if !found {
		return nil
	}

	builder := g53.NewResponseBuilder(req)
	count := int(me.answerCount + me.authorityCount + me.additionalCount)
	if count > 0 {
		builder.ResizeSection(g53.AnswerSection, int(me.answerCount)).
			ResizeSection(g53.AuthSection, int(me.authorityCount)).
			ResizeSection(g53.AdditionalSection, int(me.additionalCount))
		for i := 0; i < count; i++ {
			rrsetHash := me.rrsets[i]
			rrset := c.rrsetCache.Get(rrsetHash.keyHash, rrsetHash.conflictHash)
			if rrset == nil {
				c.remove(keyHash, conflictHash)
				return nil
			}
			if i < int(me.answerCount) {
				builder.AddRRset(g53.AnswerSection, rrset)
			} else if i < int(me.answerCount+me.authorityCount) {
				builder.AddRRset(g53.AuthSection, rrset)
			} else {
				builder.AddRRset(g53.AdditionalSection, rrset)
			}
		}
	}
	builder.SetRcode(me.rcode)
	return builder.Done()
}

func (c *MessageCache) GetCNameResponse(req *g53.Message) (*g53.Message, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	var answers []*g53.RRset
	var err error
	if req.Question.Type == g53.RR_CNAME {
		if rrset := c.getRRset(&req.Question.Name, g53.RR_CNAME); rrset != nil {
			answers = []*g53.RRset{rrset}
		}
	} else {
		answers, err = c.getCNameChain(&req.Question.Name)
		if err != nil {
			return nil, err
		}
	}

	if len(answers) == 0 {
		return nil, nil
	}

	builder := g53.NewResponseBuilder(req)
	for _, rrset := range answers {
		builder.AddRRset(g53.AnswerSection, rrset)
	}
	return builder.Done(), nil
}

func (c *MessageCache) get(keyHash, conflictHash uint64) (*MessageEntry, bool) {
	if elem, hit := c.data[keyHash]; hit {
		e := elem.Value.(*MessageEntry)
		if e.conflictHash == conflictHash && !e.IsExpire() {
			c.ll.MoveToFront(elem)
			return e, true
		}
	}
	return nil, false
}

func (c *MessageCache) Add(msg *g53.Message) {
	e, answerRRsets, authRRsets, additionRRsets := getEntriesFromMessage(msg)
	c.lock.Lock()
	if len(e.rrsets) > 0 {
		c.add(e)
	}
	c.lock.Unlock()

	c.rrsetCache.Add(answerRRsets)
	c.rrsetCache.Add(authRRsets)
	c.rrsetCache.Add(additionRRsets)
}

// remove auth and additional section from message
// but add the related rrset to rrset cache
func getEntriesFromMessage(msg *g53.Message) (MessageEntry, []RRsetEntry, []RRsetEntry, []RRsetEntry) {
	keyHash, conflictHash := util.HashQuery(&msg.Question.Name, msg.Question.Type)
	me := MessageEntry{
		keyHash:      keyHash,
		conflictHash: conflictHash,
		rcode:        msg.Header.Rcode,
	}

	answerRRsets := rrsetEntriesInSection(msg, g53.AnswerSection)
	authRRsets := rrsetEntriesInSection(msg, g53.AuthSection)
	additionRRsets := rrsetEntriesInSection(msg, g53.AdditionalSection)

	if len(answerRRsets) > 0 {
		me.answerCount = len(answerRRsets)
		rrsets := make([]RRsetHash, 0, len(answerRRsets))
		expireTime := time.Now().Add(24 * time.Hour)
		for _, e := range answerRRsets {
			rrsets = append(rrsets, RRsetHash{
				keyHash:      e.keyHash,
				conflictHash: e.conflictHash,
			})
			if expireTime.After(e.expireTime) {
				expireTime = e.expireTime
			}
		}
		me.rrsets = rrsets
		me.expireTime = expireTime
	}

	if len(authRRsets) == 1 && authRRsets[0].rrset.Type == g53.RR_SOA {
		me.authorityCount = 1
		me.rrsets = []RRsetHash{
			RRsetHash{
				keyHash:      authRRsets[0].keyHash,
				conflictHash: authRRsets[0].conflictHash,
			},
		}
		soa := authRRsets[0].rrset
		ttl := uint32(soa.Ttl)
		miniTtl := soa.Rdatas[0].(*g53.SOA).Minimum
		if ttl > miniTtl {
			ttl = miniTtl
		}
		me.expireTime = time.Now().Add(time.Duration(ttl) * time.Second)
	}
	return me, answerRRsets, authRRsets, additionRRsets
}

func rrsetEntriesInSection(msg *g53.Message, st g53.SectionType) []RRsetEntry {
	trustLevel := getRRsetTrustLevel(msg, st)
	entries := make([]RRsetEntry, 0, msg.SectionRRsetCount(st))
	for _, rrset := range msg.GetSection(st) {
		if st == g53.AdditionalSection && (rrset.Type == g53.RR_TSIG || rrset.Type == g53.RR_OPT) {
			continue
		}
		entries = append(entries, rrsetToEntry(rrset, trustLevel))
	}
	return entries
}

func rrsetToEntry(rrset *g53.RRset, trustLevel TrustLevel) RRsetEntry {
	keyHash, conflictHash := util.HashQuery(&rrset.Name, rrset.Type)
	return RRsetEntry{
		keyHash:      keyHash,
		conflictHash: conflictHash,
		rrset:        rrset,
		trustLevel:   trustLevel,
		expireTime:   time.Now().Add(time.Second * time.Duration(rrset.Ttl)),
	}
}

func (c *MessageCache) add(e MessageEntry) {
	if elem, ok := c.data[e.keyHash]; ok {
		c.ll.MoveToFront(elem)
		elem.Value = &e
	} else if c.ll.Len() < c.cap {
		elem := c.ll.PushFront(&e)
		c.data[e.keyHash] = elem
	} else {
		//reuse last elem
		back := c.ll.Back()
		oe := back.Value.(*MessageEntry)
		oe.rrsets = nil
		delete(c.data, oe.keyHash)
		*oe = e
		c.data[e.keyHash] = back
		c.ll.MoveToFront(back)
	}
}

func (c *MessageCache) AddRRset(msg *g53.Message) {
	for _, st := range []g53.SectionType{g53.AnswerSection, g53.AuthSection, g53.AdditionalSection} {
		c.rrsetCache.Add(rrsetEntriesInSection(msg, st))
	}
}

func (c *MessageCache) Remove(name *g53.Name, typ g53.RRType) bool {
	keyHash, conflictHash := util.HashQuery(name, typ)
	c.lock.Lock()
	defer c.lock.Unlock()

	return c.remove(keyHash, conflictHash)
}

func (c *MessageCache) remove(keyHash, conflictHash uint64) bool {
	if elem, hit := c.data[keyHash]; hit {
		e := elem.Value.(*MessageEntry)
		if e.conflictHash == conflictHash {
			delete(c.data, keyHash)
			c.ll.Remove(elem)
			return true
		}
	}
	return false
}

func (c *MessageCache) GetClosestNS(name *g53.Name) *g53.RRset {
	keyHash, conflictHash := util.HashQuery(name, g53.RR_NS)
	if rrset := c.rrsetCache.Get(keyHash, conflictHash); rrset != nil {
		return rrset
	} else if parent, err := name.Parent(1); err == nil {
		return c.GetClosestNS(parent)
	} else {
		return nil
	}
}

func (c *MessageCache) GetRRset(name *g53.Name, typ g53.RRType) *g53.RRset {
	return c.getRRset(name, typ)
}

func (c *MessageCache) getRRset(name *g53.Name, typ g53.RRType) *g53.RRset {
	keyHash, conflictHash := util.HashQuery(name, typ)
	return c.rrsetCache.Get(keyHash, conflictHash)
}

func (c *MessageCache) getCNameChain(name *g53.Name) ([]*g53.RRset, error) {
	var chain []*g53.RRset
	next := name
	for {
		cname := c.getRRset(next, g53.RR_CNAME)
		if cname == nil {
			break
		}

		if len(cname.Rdatas) != 1 {
			return nil, fmt.Errorf("get invalid cname rrset %s in cache",
				cname.String())
		}
		next = cname.Rdatas[0].(*g53.CName).Name
		for _, prev := range chain {
			if prev.Name.Equals(next) {
				return nil, fmt.Errorf("cname chain for %s has loop",
					name.String(false))
			}
		}
		chain = append(chain, cname)
		if len(chain) > MaxCNameChainDepth {
			return nil, fmt.Errorf("cname chain for %s exceed depth limit",
				name.String(false))
		}
	}

	return chain, nil
}
