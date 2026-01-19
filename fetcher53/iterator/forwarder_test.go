package iterator

import (
	"testing"

	ut "gitlab.alibaba-inc.com/fengjin.hf/cement/unittest"
	"gitlab.alibaba-inc.com/fengjin.hf/g53"

	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/config"
)

func TestForwarderGetDelegatinPoint(t *testing.T) {
	conf := config.ForwardConf{
		ForwardZones: []config.ForwardZone{
			config.ForwardZone{".", []string{"1.1.1.1"}},
			config.ForwardZone{"com", []string{"2.2.2.2", "3.3.3.3"}},
		},
	}
	manager, err := NewForwardManager(&conf)
	ut.Assert(t, err == nil, "")

	dp := manager.GetDelegationPoint(g53.NameFromStringUnsafe("cn"))
	ut.Assert(t, dp.Zone().Equals(g53.Root), "")

	dp = manager.GetDelegationPoint(g53.NameFromStringUnsafe("a.com"))
	ut.Assert(t, dp.Zone().Equals(g53.NameFromStringUnsafe("com")), "")
}
