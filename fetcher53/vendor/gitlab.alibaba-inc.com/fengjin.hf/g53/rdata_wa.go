package g53

import (
	"errors"
	"math"
	"net"
	"regexp"
	"strings"

	"gitlab.alibaba-inc.com/fengjin.hf/cement/buffer"
)

type WA struct {
	Weight uint16
	Host   net.IP
}

func (a *WA) Rend(r *MsgRender) error {
	if err := rendField(RDF_C_IPV4, a.Host, r); err != nil {
		return err
	}

	return rendField(RDF_C_UINT16, a.Weight, r)
}

func (a *WA) ToWire(buf *buffer.OutputBuffer) error {
	if err := fieldToWire(RDF_C_IPV4, a.Host, buf); err != nil {
		return err
	}

	return fieldToWire(RDF_C_UINT16, a.Weight, buf)
}

func (a *WA) Compare(other Rdata) int {
	return fieldCompare(RDF_C_IPV4, a.Host, other.(*WA).Host)
}

func (a *WA) String() string {
	return strings.Join([]string{
		fieldToString(RDF_D_IPV4, a.Host),
		fieldToString(RDF_D_INT, a.Weight)}, " ")
}

func WAFromWire(buf *buffer.InputBuffer, ll uint16) (*WA, error) {
	f, ll, err := fieldFromWire(RDF_C_IPV4, buf, ll)
	if err != nil {
		return nil, err
	}
	host, _ := f.(net.IP)

	f, ll, err = fieldFromWire(RDF_C_UINT16, buf, ll)
	if err != nil {
		return nil, err
	} else if ll != 0 {
		return nil, errors.New("extra data in a rdata part")
	} else {
		weight, _ := f.(uint16)
		return &WA{weight, host}, nil
	}
}

//very ugly, in string format, weight is after ip
var waRdataTemplate = regexp.MustCompile(`^\s*(\S+)\s+(\S+)\s*$`)

func WAFromString(s string) (*WA, error) {
	fields := waRdataTemplate.FindStringSubmatch(s)
	if len(fields) != 3 {
		return nil, errors.New("fields count for wa isn't 2")
	}

	fields = fields[1:]

	f, err := fieldFromString(RDF_D_IPV4, fields[0])
	if err != nil {
		return nil, err
	}
	host := f.(net.IP).To4()

	f, err = fieldFromString(RDF_D_INT, fields[1])
	if err != nil {
		return nil, err
	}
	weight, _ := f.(int)
	if weight < 0 || weight > math.MaxUint16 {
		return nil, ErrOutOfRange
	}

	return &WA{uint16(weight), host.To4()}, nil
}
