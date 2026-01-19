package iterator

import (
	"bytes"

	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/cache"
	"gitlab.alibaba-inc.com/fengjin.hf/g53"
)

type DelegationPoint struct {
	zone          g53.Name
	missingServer []g53.Name
	hosts         []Host
}

func NewDelegationPoint(zone *g53.Name, hosts []Host) *DelegationPoint {
	dp := &DelegationPoint{
		zone: zone.Clone(),
	}
	dp.hosts = make([]Host, len(hosts))
	for i, host := range hosts {
		dp.hosts[i] = CloneHost(host)
	}
	return dp
}

func NewFromReferralResponse(resp *g53.Message) *DelegationPoint {
	ns := resp.GetSection(g53.AuthSection)[0]
	dp := NewFromNSRRset(ns, nil)
	for _, rrset := range resp.GetSection(g53.AdditionalSection) {
		dp.AddGlue(rrset)
	}
	return dp
}

func NewFromNSRRset(rrset *g53.RRset, glues []*g53.RRset) *DelegationPoint {
	var missingServer []g53.Name
	for _, rdata := range rrset.Rdatas {
		name := rdata.(*g53.NS).Name
		if !name.IsSubDomain(&rrset.Name) {
			missingServer = append(missingServer, name.Clone())
		}
	}
	dp := &DelegationPoint{
		zone:          rrset.Name.Clone(),
		missingServer: missingServer,
	}
	for _, glue := range glues {
		dp.AddGlue(glue)
	}
	return dp
}

func (dp *DelegationPoint) AddGlue(glue *g53.RRset) {
	if glue.Type == g53.RR_A {
		for _, rdata := range glue.Rdatas {
			dp.hosts = append(dp.hosts, CloneHost(rdata.(*g53.A).Host))
		}

		if !glue.Name.IsSubDomain(&dp.zone) {
			dp.removeMissingServer(&glue.Name)
		}
	}
}

func NewFromCache(name *g53.Name, messageCache *cache.Cache) *DelegationPoint {
	ns := messageCache.GetClosestNS(name)
	if ns == nil {
		return nil
	}
	allGlueIsUnderZone := true
	var glues []*g53.RRset
	for _, rdata := range ns.Rdatas {
		glueName := rdata.(*g53.NS).Name
		if !glueName.IsSubDomain(&ns.Name) {
			allGlueIsUnderZone = false
		}
		if rrset := messageCache.GetRRset(glueName, g53.RR_A); rrset != nil {
			glues = append(glues, rrset)
		}
	}

	if len(glues) > 0 || !allGlueIsUnderZone {
		return NewFromNSRRset(ns, glues)
	} else if parent, err := ns.Name.Parent(1); err == nil {
		return NewFromCache(parent, messageCache)
	} else {
		return nil
	}
}

func (dp *DelegationPoint) Zone() *g53.Name {
	return &dp.zone
}

func (dp *DelegationPoint) GetTarget(hostSelector HostSelector) Host {
	return hostSelector.Select(dp.hosts)
}

func (dp *DelegationPoint) GetMissingServer() *g53.Name {
	if len(dp.missingServer) == 0 {
		return nil
	} else {
		return &dp.missingServer[0]
	}
}

func (dp *DelegationPoint) MarkHostLame(h Host) {
	hc := len(dp.hosts)
	for i, host := range dp.hosts {
		if host.Equal(h) {
			if i != hc-1 {
				dp.hosts[i] = dp.hosts[hc-1]
			}
			dp.hosts[hc-1] = nil
			dp.hosts = dp.hosts[:(hc - 1)]
			return
		}
	}
}

func (dp *DelegationPoint) MarkServerProbed(name *g53.Name) {
	dp.removeMissingServer(name)
}

func (dp *DelegationPoint) removeMissingServer(name *g53.Name) {
	nc := len(dp.missingServer)
	for i, server := range dp.missingServer {
		if name.Equals(&server) {
			if i != nc-1 {
				dp.missingServer[i] = dp.missingServer[nc-1]
			}
			dp.missingServer = dp.missingServer[:(nc - 1)]
			break
		}
	}

}

func (dp *DelegationPoint) String() string {
	var buf bytes.Buffer
	buf.WriteString("zone:")
	buf.WriteString(dp.zone.String(true))
	buf.WriteString(",server ips:")
	for _, h := range dp.hosts {
		buf.WriteString(h.String())
		buf.WriteString(",")
	}
	buf.WriteString(",missing servers:")
	for _, s := range dp.missingServer {
		buf.WriteString(s.String(true))
		buf.WriteString(",")
	}
	return buf.String()
}
