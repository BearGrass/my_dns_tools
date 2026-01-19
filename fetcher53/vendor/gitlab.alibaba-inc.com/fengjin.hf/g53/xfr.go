package g53

import (
	"gitlab.alibaba-inc.com/fengjin.hf/g53/util"
)

func MakeAXFR(zone *Name) *Message {
	q := &Question{
		Name:  *zone,
		Type:  RR_AXFR,
		Class: CLASS_IN,
	}
	return NewMsgBuilder(&Message{}).
		SetId(util.GenMessageId()).
		SetOpcode(OP_QUERY).
		SetQuestion(q).
		Done()
}

func MakeIXFR(zone *Name, currentSOA *RRset) *Message {
	q := &Question{
		Name:  *zone,
		Type:  RR_IXFR,
		Class: CLASS_IN,
	}

	return NewMsgBuilder(&Message{}).
		SetId(util.GenMessageId()).
		SetOpcode(OP_QUERY).
		SetQuestion(q).
		AddRRset(AuthSection, currentSOA).
		Done()
}
