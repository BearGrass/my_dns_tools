package iterator

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.alibaba-inc.com/fengjin.hf/cement/configure"
	ut "gitlab.alibaba-inc.com/fengjin.hf/cement/unittest"
	"gitlab.alibaba-inc.com/fengjin.hf/g53"

	msgcache "gitlab.alibaba-inc.com/fengjin.hf/fetcher53/cache"
	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/config"
	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/logger"
	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/server"
)

type TestCase struct {
	Name           string
	QueryName      string       `yaml:"qname"`
	QueryType      string       `yaml:"qtype"`
	ExpectResponse Response     `yaml:"expect_response"`
	ExpectRcode    string       `yaml:"expect_rcode"`
	Servers        []NameServer `yaml:"servers"`
}

func (tc TestCase) GetExpectResponse() *g53.Message {
	typ, _ := g53.TypeFromString(tc.QueryType)
	req := g53.NewRequestBuilder(g53.NameFromStringUnsafe(tc.QueryName),
		typ).Done()
	return tc.ExpectResponse.ToMessage(req)
}

func (tc TestCase) GetExpectRcode() g53.Rcode {
	return rcodeFromString(tc.ExpectRcode)
}

func rcodeFromString(s string) g53.Rcode {
	switch s {
	case "SERVFAIL":
		return g53.R_SERVFAIL
	case "NXDOMAIN":
		return g53.R_NXDOMAIN
	case "REFUSED":
		return g53.R_REFUSED
	default:
		return g53.R_NOERROR
	}
}

func (tc TestCase) GetRootHint() RootHint {
	ns := []string{". 518400  IN      NS a.root-servers.net."}
	for _, s := range tc.Servers {
		for _, z := range s.Zones {
			if z == "." {
				return NewRootHint(ns, []string{
					fmt.Sprintf("a.root-servers.net.        3600000 IN      A %s", s.IP),
				})
			}
		}
	}
	panic("no root server is specified in test case")
}

type Response struct {
	Answers     []string `yaml:"answer"`
	Authorities []string `yaml:"authority"`
	Additionals []string `yaml:"additional"`
}

func (r Response) ToMessage(req *g53.Message) *g53.Message {
	builder := g53.NewResponseBuilder(req)
	for _, answer := range rrsetsFromStrings(r.Answers) {
		builder.AddRRset(g53.AnswerSection, answer)
	}
	for _, auth := range rrsetsFromStrings(r.Authorities) {
		builder.AddRRset(g53.AuthSection, auth)
	}
	for _, additional := range rrsetsFromStrings(r.Additionals) {
		builder.AddRRset(g53.AdditionalSection, additional)
	}
	return builder.Done()
}

func rrsetsFromStrings(ss []string) []*g53.RRset {
	var rrsets []*g53.RRset
	var last *g53.RRset
	for _, s := range ss {
		rrset, _ := g53.RRsetFromString(s)
		if last != nil && rrset.IsSameRRset(last) {
			last.AddRdata(rrset.Rdatas[0])
		} else {
			if last != nil {
				rrsets = append(rrsets, last)
			}
			last = rrset
		}
	}
	if last != nil {
		rrsets = append(rrsets, last)
	}
	return rrsets
}

type NameServer struct {
	IP        string               `yaml:"ip"`
	Zones     []string             `yaml:"zones"`
	Responses []RequestAndResponse `yaml:"request_and_responses"`
	Rcode     string               `yaml:"rcode"`
}

func (ns NameServer) handleQuery(req *g53.Message) (*g53.Message, error) {
	qname := req.Question.Name.String(false)
	qtype := req.Question.Type.String()
	if ns.Rcode != "" && ns.Rcode != "NOERROR" {
		return g53.NewResponseBuilder(req).SetRcode(rcodeFromString(ns.Rcode)).Done(), nil
	} else {
		for _, resp := range ns.Responses {
			if resp.QueryName == qname && resp.QueryType == qtype {
				return resp.Response.ToMessage(req), nil
			}
		}
		return nil, fmt.Errorf("name server has no response for query %s", req.Question.String())
	}
}

type RequestAndResponse struct {
	QueryName string   `yaml:"qname"`
	QueryType string   `yaml:"qtype"`
	Response  Response `yaml:"response"`
}

type DumbRoundTrip struct {
	servers      []NameServer
	hostSelector HostSelector
}

func (d *DumbRoundTrip) Query(target Host, zone *g53.Name, req *g53.Message) (*g53.Message, ResponseCategory, error) {
	ip := target.String()
	for _, server := range d.servers {
		if server.IP == ip {
			resp, err := server.handleQuery(req)
			if err == nil {
				question := req.Question
				category, err := SanitizeClassifyResponse(zone, &question.Name, question.Type, resp)
				return resp, category, err
			}
		}
	}
	d.hostSelector.SetTimeout(target, IteratorTimeout)
	return nil, ServerFail, fmt.Errorf("unreacahble")
}

func buildTestCases() []TestCase {
	dir := "testcases"
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		panic("read testcase failed:" + err.Error())
	}

	cases := make([]TestCase, 0, len(files))
	for _, f := range files {
		fn := f.Name()
		if strings.HasSuffix(fn, ".yaml") {
			var c TestCase
			configure.Load(&c, filepath.Join(dir, fn))
			c.Name = strings.TrimSuffix(fn, ".yaml")
			cases = append(cases, c)
		}
	}
	return cases
}

func TestIterator(t *testing.T) {
	logger.Init("debug")
	for _, c := range buildTestCases() {
		fmt.Printf("--> Run case %s\n", c.Name)
		cache := msgcache.NewCache(1024)
		selector := NewRTTBasedHostSelector(1024)
		conf := config.ForwardConf{}
		forward, _ := NewForwardManager(&conf)
		iterator := newIterator(cache, c.GetRootHint(), selector, forward, &DumbRoundTrip{c.Servers, selector})
		qtype, _ := g53.TypeFromString(c.QueryType)
		req := g53.NewRequestBuilder(g53.NameFromStringUnsafe(c.QueryName), qtype).Done()
		ctx := &server.QueryContext{
			Request:    *req,
			TraceQuery: false,
		}
		resp, err := iterator.Resolve(ctx)
		ut.Assert(t, err == nil, "")
		expectRcode := c.GetExpectRcode()
		ut.Equal(t, expectRcode, resp.Header.Rcode)
		if expectRcode == g53.R_NOERROR {
			ut.Assert(t, messageIsEqual(c.GetExpectResponse(), resp), "")
		}
	}
}

func messageIsEqual(m1, m2 *g53.Message) bool {
	for _, section := range []g53.SectionType{g53.AnswerSection, g53.AuthSection, g53.AdditionalSection} {
		if m1.GetSection(section).String() != m2.GetSection(section).String() {
			fmt.Printf("want %s get %s\n", m1.String(), m2.String())
			return false
		}
	}
	return true
}
