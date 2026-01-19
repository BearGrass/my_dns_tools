package g53

import (
	"errors"
	"math"
	"regexp"
	"strings"

	"gitlab.alibaba-inc.com/fengjin.hf/cement/buffer"
)

type WCName struct {
	Weight uint16
	Name   *Name
}

func (c *WCName) Rend(r *MsgRender) error {
	if err := rendField(RDF_C_NAME, c.Name, r); err != nil {
		return err
	}

	return rendField(RDF_C_UINT16, c.Weight, r)
}

func (c *WCName) ToWire(buf *buffer.OutputBuffer) error {
	if err := fieldToWire(RDF_C_NAME, c.Name, buf); err != nil {
		return err
	}

	return fieldToWire(RDF_C_UINT16, c.Weight, buf)
}

func (c *WCName) String() string {
	return strings.Join([]string{
		fieldToString(RDF_D_NAME, c.Name),
		fieldToString(RDF_D_INT, c.Weight)}, " ")
}

func (c *WCName) Compare(other Rdata) int {
	return fieldCompare(RDF_C_NAME, c.Name, other.(*WCName).Name)
}

func WCNameFromWire(buf *buffer.InputBuffer, ll uint16) (*WCName, error) {
	n, ll, err := fieldFromWire(RDF_C_NAME, buf, ll)
	if err != nil {
		return nil, err
	}
	name, _ := n.(*Name)

	f, ll, err := fieldFromWire(RDF_C_UINT16, buf, ll)
	if err != nil {
		return nil, err
	} else if ll != 0 {
		return nil, errors.New("extra data in rdata part")
	} else {
		weight, _ := f.(uint16)
		return &WCName{weight, name}, nil
	}
}

var wcnameRdataTemplate = regexp.MustCompile(`^\s*(\S+)\s+(\S+)\s*$`)

func WCNameFromString(s string) (*WCName, error) {
	fields := wcnameRdataTemplate.FindStringSubmatch(s)
	if len(fields) != 3 {
		return nil, errors.New("fields count for wcname isn't 3")
	}

	fields = fields[1:]
	n, err := fieldFromString(RDF_D_NAME, fields[0])
	if err != nil {
		return nil, err
	}
	name, _ := n.(*Name)

	f, err := fieldFromString(RDF_D_INT, fields[1])
	if err != nil {
		return nil, err
	}
	weight, _ := f.(int)
	if weight < 0 || weight > math.MaxUint16 {
		return nil, ErrOutOfRange
	}

	return &WCName{uint16(weight), name}, nil
}
