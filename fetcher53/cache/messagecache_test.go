package cache

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	ut "gitlab.alibaba-inc.com/fengjin.hf/cement/unittest"
	"gitlab.alibaba-inc.com/fengjin.hf/g53"
)

func buildMessage(name string, ips []string, ttl int) *g53.Message {
	rdatas := make([]g53.Rdata, 0, len(ips))
	for _, ip := range ips {
		rdata, _ := g53.AFromString(ip)
		rdatas = append(rdatas, rdata)
	}

	req := g53.NewRequestBuilder(g53.NameFromStringUnsafe(name), g53.RR_A).Done()
	return g53.NewResponseBuilder(req).
		SetId(1000).
		AddRRset(g53.AnswerSection, &g53.RRset{
			Name:   *g53.NameFromStringUnsafe(name),
			Type:   g53.RR_A,
			Class:  g53.CLASS_IN,
			Ttl:    g53.RRTTL(ttl),
			Rdatas: rdatas,
		}).Done()
}

func TestMessageCacheFetch(t *testing.T) {
	cacheSize := 3
	cache := NewCache(cacheSize)
	ut.Equal(t, cache.Len(), 0)

	//test cache expire
	for i := 0; i < cacheSize; i++ {
		qname := fmt.Sprintf("test%d.example.com", i)
		message := buildMessage(qname, []string{"1.1.1.1"}, 3)
		cache.Add(message)
		ut.Equal(t, cache.Len(), i+1)

		request := g53.NewRequestBuilder(g53.NameFromStringUnsafe(qname), g53.RR_A).SetId(uint16(i)).Done()
		resp := cache.Get(request)
		ut.Equal(t, resp.Header.Id, uint16(i))
		ut.Equal(t, resp.SectionRRCount(g53.AnswerSection), 1)
		ut.Equal(t, resp.SectionRRCount(g53.AuthSection), 0)
	}
	<-time.After(4 * time.Second)
	for i := 0; i < cacheSize; i++ {
		qname := fmt.Sprintf("test%d.example.com", i)
		request := g53.NewRequestBuilder(g53.NameFromStringUnsafe(qname), g53.RR_A).SetId(uint16(i)).Done()
		msg := cache.Get(request)
		ut.Assert(t, msg == nil, "message should expired")
	}

	//test cache overwrite
	for i := 0; i < 2*cacheSize; i++ {
		qname := fmt.Sprintf("test%d.example.com", i)
		message := buildMessage(qname, []string{"1.1.1.1", "2.2.2.2"}, 3)
		cache.Add(message)

		request := g53.NewRequestBuilder(g53.NameFromStringUnsafe(qname), g53.RR_A).SetId(uint16(i)).Done()
		resp := cache.Get(request)
		ut.Equal(t, resp.Header.Id, uint16(i))
		ut.Equal(t, resp.SectionRRCount(g53.AnswerSection), 2)
		ut.Equal(t, resp.SectionRRCount(g53.AuthSection), 0)
	}
	ut.Equal(t, cache.Len(), cacheSize)

	for i := 0; i < 2*cacheSize; i++ {
		qname := fmt.Sprintf("test%d.example.com", i)
		request := g53.NewRequestBuilder(g53.NameFromStringUnsafe(qname), g53.RR_A).SetId(uint16(i)).Done()
		resp := cache.Get(request)
		if i < cacheSize {
			ut.Assert(t, resp == nil, "message should expire")
		} else {
			ut.Assert(t, resp != nil, "new add message shouldn't expire")
		}
	}
}

func buildNSResponse(zone string, ip_seg int) *g53.Message {
	if len(zone) > 100 {
		zone = zone[:100]
	}
	req := g53.NewRequestBuilder(g53.NameFromStringUnsafe(zone), g53.RR_NS).Done()
	nsName, _ := g53.NameFromStringUnsafe("ns").Concat(g53.NameFromStringUnsafe(zone))
	ns := &g53.NS{Name: nsName}
	glue, _ := g53.AFromString(fmt.Sprintf("%d.%d.%d.%d", ip_seg, ip_seg, ip_seg, ip_seg))
	return g53.NewResponseBuilder(req).
		SetId(1000).
		AddRRset(g53.AnswerSection, &g53.RRset{
			Name:   *g53.NameFromStringUnsafe(zone),
			Type:   g53.RR_NS,
			Class:  g53.CLASS_IN,
			Ttl:    g53.RRTTL(100),
			Rdatas: []g53.Rdata{ns},
		}).
		AddRRset(g53.AdditionalSection, &g53.RRset{
			Name:   *nsName,
			Type:   g53.RR_A,
			Class:  g53.CLASS_IN,
			Ttl:    g53.RRTTL(100),
			Rdatas: []g53.Rdata{glue},
		}).
		Done()
}

func TestDeepestNS(t *testing.T) {
	cache := NewCache(100)
	cache.Add(buildNSResponse(".", 1))
	cache.Add(buildNSResponse("com.", 2))
	cache.Add(buildNSResponse("alibaba.com.", 3))

	cases := []struct {
		queryZone string
		getZone   string
		exist     bool
	}{
		{"a.alibaba.com.", "alibaba.com.", true},
		{"a.b.c.alibaba.com.", "alibaba.com.", true},
		{"a.com.", "com.", true},
		{"a.b.c.com.", "com.", true},
		{"a.cn.", ".", true},
		{"a.ali.cn.", ".", true},
	}

	for _, c := range cases {
		rrset := cache.GetClosestNS(g53.NameFromStringUnsafe(c.queryZone))
		if c.exist {
			ut.Assert(t, rrset != nil, "")
			ut.Equal(t, rrset.Name.String(false), c.getZone)
		} else {
			ut.Assert(t, rrset == nil, "")
		}
	}
}

func buildCNameResponse(nameChain []string) *g53.Message {
	from := g53.NameFromStringUnsafe(nameChain[0])
	req := g53.NewRequestBuilder(from, g53.RR_A).Done()
	builder := g53.NewResponseBuilder(req).SetId(1000)
	for _, s := range nameChain[1:] {
		to := g53.NameFromStringUnsafe(s)
		builder.AddRRset(g53.AnswerSection, &g53.RRset{
			Name:   *from,
			Type:   g53.RR_CNAME,
			Class:  g53.CLASS_IN,
			Ttl:    g53.RRTTL(100),
			Rdatas: []g53.Rdata{&g53.CName{to}},
		})
		from = to
	}
	return builder.Done()
}

func TestGetCNameResponse(t *testing.T) {
	cache := NewCache(100)
	cache.Add(buildCNameResponse([]string{"a", "b", "c", "d"}))

	cases := []struct {
		name        string
		answerCount int
		qtype       g53.RRType
	}{
		{"a", 3, g53.RR_A},
		{"b", 2, g53.RR_A},
		{"c", 1, g53.RR_A},
		{"d", 0, g53.RR_A},
		{"a.cn.", 0, g53.RR_A},
		{"a", 1, g53.RR_CNAME},
		{"b", 1, g53.RR_CNAME},
		{"c", 1, g53.RR_CNAME},
		{"d", 0, g53.RR_CNAME},
		{"a.cn.", 0, g53.RR_CNAME},
	}

	for _, c := range cases {
		request := g53.NewRequestBuilder(g53.NameFromStringUnsafe(c.name), c.qtype).Done()
		resp, _ := cache.GetCNameResponse(request)
		if c.answerCount == 0 {
			ut.Assert(t, resp == nil, "")
		} else {
			ut.Equal(t, resp.SectionRRsetCount(g53.AnswerSection), c.answerCount)
		}
	}

	cache.Add(buildCNameResponse([]string{"e", "f", "e"}))
	request := g53.NewRequestBuilder(g53.NameFromStringUnsafe("e"), g53.RR_A).Done()
	_, err := cache.GetCNameResponse(request)
	ut.Assert(t, err != nil, "")

	chain := make([]string, 0, 15)
	for i := 0; i < 15; i++ {
		chain = append(chain, fmt.Sprintf("g%d", i))
	}
	cache.Add(buildCNameResponse(chain))
	request = g53.NewRequestBuilder(g53.NameFromStringUnsafe("g0"), g53.RR_A).Done()
	_, err = cache.GetCNameResponse(request)
	ut.Assert(t, err != nil, "")
}

func TestDataRace(t *testing.T) {
	cache := NewCache(100)
	msgCount := 700

	var wg sync.WaitGroup
	writerCount := 5
	wg.Add(writerCount)
	for i := 0; i < writerCount; i++ {
		go func() {
			defer wg.Done()
			for i := 0; i < msgCount; i++ {
				cache.Add(buildNSResponse(g53.RandomNoneFQDNDomain(), 1))
				s := rand.Intn(10)
				<-time.After(time.Duration(s) * time.Millisecond)
			}
		}()
	}

	queryCount := 300
	readCount := 15
	wg.Add(readCount)
	for i := 0; i < readCount; i++ {
		go func() {
			defer wg.Done()
			for i := 0; i < queryCount; i++ {
				cache.GetClosestNS(g53.NameFromStringUnsafe(g53.RandomNoneFQDNDomain()))
				s := rand.Intn(10)
				<-time.After(time.Duration(s) * time.Millisecond)
				req := g53.NewRequestBuilder(g53.NameFromStringUnsafe(g53.RandomNoneFQDNDomain()), g53.RR_NS).Done()
				cache.Get(req)
			}
		}()
	}

	wg.Wait()
	ut.Equal(t, cache.Len(), 100)
}
