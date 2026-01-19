package g53

import (
	"fmt"
	"net"

	"gitlab.alibaba-inc.com/fengjin.hf/cement/buffer"
)

const (
	EDNS_SUBNET = 8
)

type SubnetOpt struct {
	Family uint16
	Mask   uint8
	Scope  uint8
	Ip     net.IP
}

func (subnet *SubnetOpt) Rend(render *MsgRender) {
	render.WriteUint16(EDNS_SUBNET)
	ipLen := uint(subnet.Mask / 8)
	if subnet.Mask%8 != 0 {
		ipLen += 1
	}

	render.WriteUint16(uint16(2 + 2 + ipLen))
	render.WriteUint16(subnet.Family)
	render.WriteUint8(subnet.Mask)
	render.WriteUint8(subnet.Scope)
	var ipToWrite net.IP
	if subnet.Family == 1 {
		ipToWrite = subnet.Ip.To4().Mask(net.CIDRMask(int(subnet.Mask), net.IPv4len*8))
	} else {
		ipToWrite = subnet.Ip.To16().Mask(net.CIDRMask(int(subnet.Mask), net.IPv6len*8))
	}
	render.WriteData([]byte(ipToWrite)[0:ipLen])
}

func (subnet *SubnetOpt) String() string {
	return fmt.Sprintf("; CLIENT-SUBNET: %s/%d/%d\n", subnet.Ip.String(), subnet.Mask, subnet.Scope)
}

//read from OPTION-LENGTH
func subnetOptFromWire(buf *buffer.InputBuffer) (Option, error) {
	l, _ := buf.ReadUint16()
	family, _ := buf.ReadUint16()
	mask, _ := buf.ReadUint8()
	scope, _ := buf.ReadUint8()
	var ip net.IP
	switch family {
	case 1:
		addr := make([]byte, 4)
		addr_data, _ := buf.ReadBytes(uint(l - 4))
		copy(addr, addr_data)
		ip = net.IPv4(addr[0], addr[1], addr[2], addr[3])
	case 2:
		addr := make([]byte, 16)
		addr_data, _ := buf.ReadBytes(uint(l - 4))
		copy(addr, addr_data)
		ip = net.IP{addr[0], addr[1], addr[2], addr[3], addr[4],
			addr[5], addr[6], addr[7], addr[8], addr[9], addr[10],
			addr[11], addr[12], addr[13], addr[14], addr[15]}
	}

	if ip != nil {
		return &SubnetOpt{Family: family,
			Mask:  mask,
			Scope: scope,
			Ip:    ip}, nil
	} else {
		return nil, fmt.Errorf("unkown family")
	}
}

func subnetOptFromRdata(rdata Rdata) Option {
	data := rdata.(*OPT).Data
	if len(data) == 0 {
		return nil
	}

	buf := buffer.NewInputBuffer(data)
	code, _ := buf.ReadUint16()
	if code != EDNS_SUBNET {
		return nil
	}

	opt, _ := subnetOptFromWire(buf)
	return opt
}

func (e *EDNS) AddSubnetV4(ip_ string) error {
	if ip := net.ParseIP(ip_); ip != nil {
		e.Options = append(e.Options, &SubnetOpt{
			Family: 1,
			Mask:   32,
			Scope:  0,
			Ip:     ip,
		})
		return nil
	} else {
		return fmt.Errorf("invalid ip address:%s", ip_)
	}
}
