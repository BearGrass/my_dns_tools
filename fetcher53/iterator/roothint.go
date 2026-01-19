package iterator

import "gitlab.alibaba-inc.com/fengjin.hf/g53"

var RootServers = []string{
	".                  518400  IN      NS      b.root-servers.net.",
	".                  518400  IN      NS      m.root-servers.net.",
	".                  518400  IN      NS      i.root-servers.net.",
	".                  518400  IN      NS      g.root-servers.net.",
	".                  518400  IN      NS      d.root-servers.net.",
	".                  518400  IN      NS      a.root-servers.net.",
	".                  518400  IN      NS      h.root-servers.net.",
	".                  518400  IN      NS      k.root-servers.net.",
	".                  518400  IN      NS      l.root-servers.net.",
	".                  518400  IN      NS      f.root-servers.net.",
	".                  518400  IN      NS      e.root-servers.net.",
	".                  518400  IN      NS      j.root-servers.net.",
	".                  518400  IN      NS      c.root-servers.net.",
}

var RootGlues = []string{
	"a.root-servers.net.        3600000 IN      A       198.41.0.4",
	"b.root-servers.net.        3600000 IN      A       199.9.14.201",
	"c.root-servers.net.        3600000 IN      A       192.33.4.12",
	"d.root-servers.net.        3600000 IN      A       199.7.91.13",
	"e.root-servers.net.        3600000 IN      A       192.203.230.10",
	"f.root-servers.net.        3600000 IN      A       192.5.5.241",
	"g.root-servers.net.        3600000 IN      A       192.112.36.4",
	"h.root-servers.net.        3600000 IN      A       198.97.190.53",
	"i.root-servers.net.        3600000 IN      A       192.36.148.17",
	"j.root-servers.net.        3600000 IN      A       192.58.128.30",
	"k.root-servers.net.        3600000 IN      A       193.0.14.129",
	"l.root-servers.net.        3600000 IN      A       199.7.83.42",
	"m.root-servers.net.        3600000 IN      A       202.12.27.33",
}

type RootHint struct {
	dp *DelegationPoint
}

func NewRootHint(rootNS, rootGlues []string) RootHint {
	ns, _ := g53.RRsetFromString(rootNS[0])
	for _, s := range rootNS[1:] {
		rrset, _ := g53.RRsetFromString(s)
		ns.AddRdata(rrset.Rdatas[0])
	}

	glues := make([]*g53.RRset, 0, len(rootGlues))
	for _, s := range rootGlues {
		rrset, _ := g53.RRsetFromString(s)
		glues = append(glues, rrset)
	}

	return RootHint{
		dp: NewFromNSRRset(ns, glues),
	}
}

func (h RootHint) GetDelegationPoint() *DelegationPoint {
	return h.dp
}
