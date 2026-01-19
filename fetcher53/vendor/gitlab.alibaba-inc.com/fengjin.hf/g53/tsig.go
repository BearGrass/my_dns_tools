package g53

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gitlab.alibaba-inc.com/fengjin.hf/cement/buffer"
)

type TsigHeader struct {
	Name     Name
	Rrtype   RRType
	Class    RRClass
	Ttl      RRTTL
	Rdlength uint16
}

func (h *TsigHeader) Rend(r *MsgRender) error {
	if err := h.Name.Rend(r); err != nil {
		return err
	}

	if err := h.Rrtype.Rend(r); err != nil {
		return err
	}

	if err := h.Class.Rend(r); err != nil {
		return err
	}

	if err := h.Ttl.Rend(r); err != nil {
		return err
	}

	return r.Skip(2)
}

func (h *TsigHeader) ToWire(buf *buffer.OutputBuffer) error {
	if err := h.Name.ToWire(buf); err != nil {
		return err
	}

	if err := h.Rrtype.ToWire(buf); err != nil {
		return err
	}

	if err := h.Class.ToWire(buf); err != nil {
		return err
	}

	if err := h.Ttl.ToWire(buf); err != nil {
		return err
	}

	return buf.Skip(2)
}

func (h *TsigHeader) String() string {
	var s []string
	s = append(s, h.Name.String(false))
	s = append(s, h.Ttl.String())
	s = append(s, h.Class.String())
	s = append(s, h.Rrtype.String())
	return strings.Join(s, "\t")
}

type Tsig struct {
	Header     TsigHeader
	Algorithm  TsigAlgorithm
	TimeSigned uint64
	Fudge      uint16
	MACSize    uint16
	MAC        []byte
	OrigId     uint16
	Error      uint16
	OtherLen   uint16
	OtherData  []byte
}

func TsigFromWire(buf *buffer.InputBuffer, ll uint16) (*Tsig, error) {
	i, ll, err := fieldFromWire(RDF_C_NAME, buf, ll)
	if err != nil {
		return nil, err
	}

	algo, err := AlgorithmFromString(i.(*Name).String(false))
	if err != nil {
		return nil, err
	}

	i, ll, err = fieldFromWire(RDF_C_UINT16, buf, ll)
	if err != nil {
		return nil, err
	}
	ts1, _ := i.(uint16)

	i, ll, err = fieldFromWire(RDF_C_UINT32, buf, ll)
	if err != nil {
		return nil, err
	}
	ts2, _ := i.(uint32)

	i, ll, err = fieldFromWire(RDF_C_UINT16, buf, ll)
	if err != nil {
		return nil, err
	}
	fudge, _ := i.(uint16)

	i, ll, err = fieldFromWire(RDF_C_UINT16, buf, ll)
	if err != nil {
		return nil, err
	}
	macSize, _ := i.(uint16)

	i, _, err = fieldFromWire(RDF_C_BINARY, buf, macSize)
	if err != nil {
		return nil, err
	}
	ll -= macSize
	mac, _ := i.([]byte)

	i, ll, err = fieldFromWire(RDF_C_UINT16, buf, ll)
	if err != nil {
		return nil, err
	}
	oid, _ := i.(uint16)

	i, ll, err = fieldFromWire(RDF_C_UINT16, buf, ll)
	if err != nil {
		return nil, err
	}
	erro, _ := i.(uint16)

	i, ll, err = fieldFromWire(RDF_C_UINT16, buf, ll)
	if err != nil {
		return nil, err
	}
	len, _ := i.(uint16)

	i, _, err = fieldFromWire(RDF_C_BINARY, buf, len)
	if err != nil {
		return nil, err
	}
	ll -= len
	odata, _ := i.([]byte)

	if ll != 0 {
		return nil, errors.New("extra data in rdata part")
	}

	return &Tsig{
		Algorithm:  algo,
		TimeSigned: ((uint64(ts1) & 0x000000000000ffff) << 32) + uint64(ts2),
		Fudge:      fudge,
		MACSize:    macSize,
		MAC:        mac,
		OrigId:     oid,
		Error:      erro,
		OtherLen:   len,
		OtherData:  odata,
	}, nil
}

func TsigFromRRset(rrset *RRset) (*Tsig, error) {
	if len(rrset.Rdatas) != 1 {
		return nil, fmt.Errorf("tsig rrset should has one rdata")
	}

	tsig := rrset.Rdatas[0].(*Tsig)
	tsig.Header = TsigHeader{
		Name:   rrset.Name,
		Rrtype: rrset.Type,
		Class:  rrset.Class,
		Ttl:    rrset.Ttl,
	}
	return tsig, nil
}

func (t *Tsig) Rend(r *MsgRender) error {
	t.Header.Rend(r)
	pos := r.Len()
	alg, _ := NameFromString(string(t.Algorithm))
	alg.Rend(r)
	ts1 := uint16((t.TimeSigned & 0x0000ffff00000000) >> 32)
	ts2 := uint32(t.TimeSigned & 0x00000000ffffffff)

	if r.LeftSpace() < 2+4+2+2+len(t.MAC)+2+2+2+len(t.OtherData) {
		return fmt.Errorf("no data in redner for tsig")
	}

	r.WriteUint16(ts1)
	r.WriteUint32(ts2)
	r.WriteUint16(t.Fudge)
	r.WriteUint16(t.MACSize)
	r.WriteData(t.MAC)
	r.WriteUint16(t.OrigId)
	r.WriteUint16(t.Error)
	r.WriteUint16(t.OtherLen)
	r.WriteData(t.OtherData)
	r.WriteUint16At(pos-2, uint16(r.Len()-pos))
	return nil
}

func (t *Tsig) ToWire(buf *buffer.OutputBuffer) error {
	t.Header.ToWire(buf)
	pos := buf.Len()
	alg, _ := NameFromString(string(t.Algorithm))
	alg.ToWire(buf)
	ts1 := uint16((t.TimeSigned & 0x0000ffff00000000) >> 32)
	ts2 := uint32(t.TimeSigned & 0x00000000ffffffff)

	if buf.LeftSpace() < 2+4+2+2+len(t.MAC)+2+2+2+len(t.OtherData) {
		return fmt.Errorf("no data in redner for tsig")
	}

	buf.WriteUint16(ts1)
	buf.WriteUint32(ts2)
	buf.WriteUint16(t.Fudge)
	buf.WriteUint16(t.MACSize)
	buf.WriteData(t.MAC)
	buf.WriteUint16(t.OrigId)
	buf.WriteUint16(t.Error)
	buf.WriteUint16(t.OtherLen)
	buf.WriteData(t.OtherData)
	buf.WriteUint16At(pos-2, uint16(buf.Len()-pos))
	return nil
}

func (t *Tsig) String() string {
	var s []string
	s = append(s, t.Header.String())
	s = append(s, "\t")
	s = append(s, string(t.Algorithm))
	s = append(s, tsigTimeToString(t.TimeSigned))
	s = append(s, strconv.Itoa(int(t.Fudge)))
	s = append(s, strconv.Itoa(int(t.MACSize)))
	s = append(s, strings.ToUpper(hex.EncodeToString(t.MAC)))
	s = append(s, strconv.Itoa(int(t.OrigId)))
	s = append(s, strconv.Itoa(int(t.Error)))
	s = append(s, strconv.Itoa(int(t.OtherLen)))
	s = append(s, string(t.OtherData))
	return strings.Join(s, " ")
}

func tsigTimeToString(t uint64) string {
	ti := time.Unix(int64(t), 0).UTC()
	return ti.Format("20060102150405")
}

func (t *Tsig) Compare(other Rdata) int {
	return 0
}

func (tsig *Tsig) IsTimeValid() bool {
	now := uint64(time.Now().Unix())
	ti := now - tsig.TimeSigned
	if now < tsig.TimeSigned {
		ti = tsig.TimeSigned - now
	}
	return uint64(tsig.Fudge) >= ti
}
