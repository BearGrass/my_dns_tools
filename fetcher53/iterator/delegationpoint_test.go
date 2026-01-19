package iterator

import (
	"net"
	"testing"
	"time"

	"gitlab.alibaba-inc.com/fengjin.hf/cement/buffer"
	ut "gitlab.alibaba-inc.com/fengjin.hf/cement/unittest"
	"gitlab.alibaba-inc.com/fengjin.hf/g53"
	"gitlab.alibaba-inc.com/fengjin.hf/g53/util"
)

func TestDelegationPointNoMissingServer(t *testing.T) {
	ns, _ := g53.RRsetFromString("com. 3600  IN NS ns1.com")
	ns2Rdata, _ := g53.RdataFromString(g53.RR_NS, "ns2.com")
	ns.AddRdata(ns2Rdata)
	glue1, _ := g53.RRsetFromString("ns1.com. 3600  IN A 1.1.1.1")
	glue2, _ := g53.RRsetFromString("ns2.com. 3600  IN A 2.2.2.2")
	dp := NewFromNSRRset(ns, []*g53.RRset{glue1, glue2})
	ut.Assert(t, dp.GetMissingServer() == nil, "")

	selector := NewRTTBasedHostSelector(100)
	selector.SetRTT(net.ParseIP("1.1.1.1"), time.Second)
	ut.Equal(t, dp.GetTarget(selector).String(), "2.2.2.2")
	selector.SetRTT(net.ParseIP("2.2.2.2"), 3*time.Second)
	ut.Equal(t, dp.GetTarget(selector).String(), "1.1.1.1")
}

func TestDelegationPointWithMissingServer(t *testing.T) {
	ns, _ := g53.RRsetFromString("com. 3600  IN NS ns1.com")
	ns2Rdata, _ := g53.RdataFromString(g53.RR_NS, "ns2.cn")
	ns.AddRdata(ns2Rdata)
	glue1, _ := g53.RRsetFromString("ns1.com. 3600  IN A 1.1.1.1")
	glue2, _ := g53.RRsetFromString("ns1.com. 3600  IN A 2.2.2.2")
	dp := NewFromNSRRset(ns, []*g53.RRset{glue1, glue2})
	ut.Equal(t, dp.GetMissingServer().String(false), "ns2.cn.")

	glue3, _ := g53.RRsetFromString("ns2.cn. 3600  IN A 3.3.3.3")
	dp.AddGlue(glue3)
	ut.Assert(t, dp.GetMissingServer() == nil, "")

	selector := NewRTTBasedHostSelector(100)
	selector.SetRTT(net.ParseIP("1.1.1.1"), time.Second)
	selector.SetRTT(net.ParseIP("2.2.2.2"), 3*time.Second)
	ut.Equal(t, dp.GetTarget(selector).String(), "3.3.3.3")
	dp.MarkHostLame(net.ParseIP("3.3.3.3"))
	ut.Equal(t, dp.GetTarget(selector).String(), "1.1.1.1")
}

func TestDelegationPointFromResp(t *testing.T) {
	raw := "d966810000010000000d001b0570646e733108756c747261646e73036e65740000010001c01b000200010002a300001101660c67746c642d73657276657273c01bc01b000200010002a30000040162c032c01b000200010002a3000004016cc032c01b000200010002a30000040165c032c01b000200010002a3000004016ac032c01b000200010002a30000040168c032c01b000200010002a30000040167c032c01b000200010002a30000040161c032c01b000200010002a30000040164c032c01b000200010002a3000004016bc032c01b000200010002a30000040163c032c01b000200010002a3000004016dc032c01b000200010002a30000040169c032c0ad000100010002a3000004c005061ec04d000100010002a3000004c0210e1ec0dd000100010002a3000004c01a5c1ec0bd000100010002a3000004c01f501ec06d000100010002a3000004c00c5e1ec030000100010002a3000004c023331ec09d000100010002a3000004c02a5d1ec08d000100010002a3000004c036701ec0fd000100010002a3000004c02bac1ec07d000100010002a3000004c0304f1ec0cd000100010002a3000004c034b21ec05d000100010002a3000004c029a21ec0ed000100010002a3000004c037531ec0ad001c00010002a300001020010503a83e00000000000000020030c04d001c00010002a300001020010503231d00000000000000020030c0dd001c00010002a30000102001050383eb00000000000000000030c0bd001c00010002a300001020010500856e00000000000000000030c06d001c00010002a3000010200105021ca100000000000000000030c030001c00010002a300001020010503d41400000000000000000030c09d001c00010002a300001020010503eea300000000000000000030c08d001c00010002a30000102001050208cc00000000000000000030c0fd001c00010002a30000102001050339c100000000000000000030c07d001c00010002a300001020010502709400000000000000000030c0cd001c00010002a3000010200105030d2d00000000000000000030c05d001c00010002a300001020010500d93700000000000000000030c0ed001c00010002a300001020010501b1f9000000000000000000300000291000000000000000"
	wire, _ := util.HexStrToBytes(raw)
	buf := buffer.NewInputBuffer(wire)
	resp, _ := g53.MessageFromWire(buf)
	dp := NewFromReferralResponse(resp)
	ut.Assert(t, dp != nil, "")
}
