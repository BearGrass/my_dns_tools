package iterator

import (
	"container/list"
	"math"
	"net"
	"sync"
	"time"
)

type Host = net.IP

func CloneHost(h Host) Host {
	o := make([]byte, len(h))
	copy(o, h)
	return o
}

type HostSelector interface {
	SetRTT(Host, time.Duration)
	SetTimeout(Host, time.Duration)
	Select([]Host) Host
}

const (
	MaxTimeoutCount            = 3
	TimeoutServerSleepInterval = 10 * time.Second
	ServerInitRTT              = time.Duration(0)
)

var _ HostSelector = &RTTBasedHostSelector{}

type HostState struct {
	hostKey      string
	rtt          time.Duration
	timeoutCount int
	wakeupTime   *time.Time
}

func NewHostState(host Host, rtt time.Duration) *HostState {
	return &HostState{
		hostKey:      host.String(),
		rtt:          rtt,
		timeoutCount: 0,
		wakeupTime:   nil,
	}
}

func NewHostStateWithTimeout(host Host, timeout time.Duration) *HostState {
	return &HostState{
		hostKey:      host.String(),
		rtt:          timeout,
		timeoutCount: 1,
		wakeupTime:   nil,
	}
}

func (h *HostState) SetRTT(rtt time.Duration) {
	if h.timeoutCount > 0 {
		h.timeoutCount = 0
		h.wakeupTime = nil
	}
	h.rtt = calculateRTT(h.rtt, rtt)
}

func calculateRTT(last, now time.Duration) time.Duration {
	return (last*7 + now*3) / 10
}

func (h *HostState) SetTimeout(timeout time.Duration) {
	if h.timeoutCount < MaxTimeoutCount {
		h.timeoutCount += 1
		h.rtt = calculateRTT(h.rtt, timeout)
	}

	if h.timeoutCount == MaxTimeoutCount {
		wakeupTime := time.Now().Add(TimeoutServerSleepInterval)
		h.wakeupTime = &wakeupTime
	}
}

func (h *HostState) IsUsable() bool {
	if h.wakeupTime != nil {
		return time.Now().After(*h.wakeupTime)
	} else {
		return true
	}
}

func (h *HostState) GetRTT() time.Duration {
	return h.rtt
}

type RTTBasedHostSelector struct {
	capacity int
	data     map[string]*list.Element
	ll       *list.List
	mu       sync.Mutex
}

func NewRTTBasedHostSelector(capacity int) *RTTBasedHostSelector {
	return &RTTBasedHostSelector{
		capacity: capacity,
		data:     make(map[string]*list.Element),
		ll:       list.New(),
	}
}

func (s *RTTBasedHostSelector) SetRTT(h Host, rtt time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if e := s.getEntry(h); e != nil {
		e.SetRTT(rtt)
	} else {
		hs := NewHostState(CloneHost(h), rtt)
		s.addEntry(hs)
	}
}

func (s *RTTBasedHostSelector) SetTimeout(h Host, timeout time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if e := s.getEntry(h); e != nil {
		e.SetTimeout(timeout)
	} else {
		hs := NewHostStateWithTimeout(CloneHost(h), timeout)
		s.addEntry(hs)
	}
}

func (s *RTTBasedHostSelector) Select(hosts []Host) Host {
	s.mu.Lock()
	defer s.mu.Unlock()

	minRTT := time.Duration(math.MaxInt64)
	index := -1
	for i, h := range hosts {
		e := s.getEntry(h)
		//always use unvisited host
		if e == nil {
			return h
		}

		if e.IsUsable() {
			rtt := e.GetRTT()
			if minRTT > rtt {
				index = i
				minRTT = rtt
			}
		}
	}

	if index != -1 {
		return hosts[index]
	} else {
		return nil
	}
}

func (s *RTTBasedHostSelector) getEntry(host Host) *HostState {
	if elem, hit := s.data[host.String()]; hit {
		e := elem.Value.(*HostState)
		s.ll.MoveToFront(elem)
		return e
	} else {
		return nil
	}
}

func (s *RTTBasedHostSelector) addEntry(hs *HostState) {
	if s.ll.Len() < s.capacity {
		elem := s.ll.PushFront(hs)
		s.data[hs.hostKey] = elem
	} else {
		elem := s.ll.Back()
		old := elem.Value.(*HostState)
		delete(s.data, old.hostKey)
		*old = *hs
		s.data[hs.hostKey] = elem
		s.ll.MoveToFront(elem)
	}
}
