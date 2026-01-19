package cache

import (
	"container/list"
	"sync"
	"time"

	"gitlab.alibaba-inc.com/fengjin.hf/g53"
)

type RRsetEntry struct {
	keyHash      uint64
	conflictHash uint64
	rrset        *g53.RRset
	trustLevel   TrustLevel
	expireTime   time.Time
}

func (e *RRsetEntry) IsExpire() bool {
	return e.expireTime.Before(time.Now())
}

type RRsetCache struct {
	cap  int
	lock sync.Mutex
	data map[uint64]*list.Element
	ll   *list.List
}

func newRRsetCache(cap int) *RRsetCache {
	return &RRsetCache{
		cap:  cap,
		data: make(map[uint64]*list.Element),
		ll:   list.New(),
	}
}

func (c *RRsetCache) Add(es []RRsetEntry) {
	c.lock.Lock()
	defer c.lock.Unlock()

	for i, e := range es {
		if elem, ok := c.data[e.keyHash]; ok {
			oe := elem.Value.(*RRsetEntry)
			if !oe.IsExpire() && e.trustLevel < oe.trustLevel {
				return
			}
			c.ll.MoveToFront(elem)
			elem.Value = &es[i]
		} else if c.ll.Len() < c.cap {
			elem := c.ll.PushFront(&es[i])
			c.data[e.keyHash] = elem
		} else {
			//reuse last elem
			back := c.ll.Back()
			oe := back.Value.(*RRsetEntry)
			delete(c.data, oe.keyHash)
			oe.rrset = nil
			*oe = e
			c.data[e.keyHash] = back
			c.ll.MoveToFront(back)
		}
	}
}

func (c *RRsetCache) Get(keyHash, conflictHash uint64) *g53.RRset {
	c.lock.Lock()
	defer c.lock.Unlock()

	if elem, hit := c.data[keyHash]; hit {
		e := elem.Value.(*RRsetEntry)
		now := time.Now()
		if e.conflictHash == conflictHash && e.expireTime.After(now) {
			c.ll.MoveToFront(elem)
			e.rrset.RotateRdata()
			rrset := e.rrset.Clone()
			rrset.Ttl = g53.RRTTL(e.expireTime.Sub(now).Seconds())
			return rrset
		}
	}
	return nil
}

func (c *RRsetCache) Has(keyHash, conflictHash uint64) bool {
	c.lock.Lock()
	defer c.lock.Unlock()

	if elem, hit := c.data[keyHash]; hit {
		e := elem.Value.(*RRsetEntry)
		return e.conflictHash == conflictHash && e.expireTime.After(time.Now())
	} else {
		return false
	}
}

func (c *RRsetCache) Remove(keyHash, conflictHash uint64) bool {
	c.lock.Lock()
	defer c.lock.Unlock()

	if elem, hit := c.data[keyHash]; hit {
		e := elem.Value.(*RRsetEntry)
		if e.conflictHash == conflictHash {
			delete(c.data, keyHash)
			c.ll.Remove(elem)
			return true
		}
	}
	return false
}
