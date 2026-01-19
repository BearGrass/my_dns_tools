package g53

import (
	"fmt"

	"gitlab.alibaba-inc.com/fengjin.hf/cement/buffer"
)

type OPT struct {
	Data []uint8
}

func (opt *OPT) Rend(r *MsgRender) error {
	return rendField(RDF_C_BINARY, opt.Data, r)
}

func (opt *OPT) ToWire(buf *buffer.OutputBuffer) error {
	return fieldToWire(RDF_C_BINARY, opt.Data, buf)
}

func (opt *OPT) Compare(other Rdata) int {
	return fieldCompare(RDF_C_BINARY, opt.Data, other.(*OPT).Data)
}

func (opt *OPT) String() string {
	return fieldToString(RDF_D_HEX, opt.Data)
}

func OPTFromWire(buf *buffer.InputBuffer, ll uint16) (*OPT, error) {
	f, ll, err := fieldFromWire(RDF_C_BINARY, buf, ll)

	if err != nil {
		return nil, err
	} else if ll != 0 {
		return nil, fmt.Errorf("extra data %d in opt rdata part", ll)
	} else {
		d, _ := f.([]uint8)
		return &OPT{d}, nil
	}
}

func OPTFromString(s string) (*OPT, error) {
	f, err := fieldFromString(RDF_D_HEX, s)
	if err == nil {
		d, _ := f.([]uint8)
		return &OPT{d}, nil
	} else {
		return nil, err
	}
}
