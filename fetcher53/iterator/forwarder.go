package iterator

import (
	"fmt"
	"net"

	"gitlab.alibaba-inc.com/fengjin.hf/cement/domaintree"
	"gitlab.alibaba-inc.com/fengjin.hf/g53"

	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/config"
)

type ForwardManager struct {
	zoneForwarders *domaintree.DomainTree
}

func NewForwardManager(conf *config.ForwardConf) (*ForwardManager, error) {
	forwarders := domaintree.NewDomainTree()
	for _, forwardZoneConf := range conf.ForwardZones {
		name, err := g53.NameFromString(forwardZoneConf.Zone)
		if err != nil {
			return nil, err
		}
		hosts := make([]Host, 0, len(forwardZoneConf.ServerAddrs))
		for _, addr := range forwardZoneConf.ServerAddrs {
			if ip := net.ParseIP(addr); ip == nil {
				return nil, fmt.Errorf("invalid addr %s", addr)
			} else {
				hosts = append(hosts, ip)
			}
		}
		if err := forwarders.Insert(name, hosts); err != nil {
			return nil, err
		}
	}

	return &ForwardManager{
		zoneForwarders: forwarders,
	}, nil
}

func (m *ForwardManager) GetDelegationPoint(name *g53.Name) *DelegationPoint {
	zone, hosts, match := m.zoneForwarders.Search(name)
	if match == domaintree.NotFound {
		return nil
	} else {
		return NewDelegationPoint(zone, hosts.([]Host))
	}
}
