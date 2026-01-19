package g53

import (
	"gitlab.alibaba-inc.com/fengjin.hf/g53/util"
)

func NewUpdateMsgBuilder(zone *Name) MsgBuilder {
	q := &Question{
		Name:  *zone,
		Type:  RR_SOA,
		Class: CLASS_IN,
	}
	return NewMsgBuilder(&Message{}).SetOpcode(OP_UPDATE).SetId(util.GenMessageId()).SetQuestion(q)
}

//at least one rr with a specified name must exist
func (b MsgBuilder) UpdateNameExists(names []*Name) MsgBuilder {
	for _, name := range names {
		b.AddRRset(AnswerSection, &RRset{
			Name:  *name,
			Type:  RR_ANY,
			Class: CLASS_ANY,
			Ttl:   0,
		})
	}
	return b
}

// no rr of any type has specified name
func (b MsgBuilder) UpdateNameNotExists(names []*Name) MsgBuilder {
	for _, name := range names {
		b.AddRRset(AnswerSection, &RRset{
			Name:  *name,
			Type:  RR_ANY,
			Class: CLASS_NONE,
			Ttl:   0,
		})
	}
	return b
}

//rrset with specified rdata exists
func (b MsgBuilder) UpdateRdataExsits(rrset *RRset) MsgBuilder {
	b.AddRRset(AnswerSection, rrset)
	return b
}

//rrset exists, (rr with name, type  exists)
func (b MsgBuilder) UpdateRRsetExists(rrset *RRset) MsgBuilder {
	b.AddRRset(AnswerSection, &RRset{
		Name:  rrset.Name,
		Type:  rrset.Type,
		Class: CLASS_ANY,
		Ttl:   0,
	})
	return b
}

//rrset not exists,(rr with name type doesn't exists)
func (b MsgBuilder) UpdateRRsetNotExists(rrset *RRset) MsgBuilder {
	b.AddRRset(AnswerSection, &RRset{
		Name:  rrset.Name,
		Type:  rrset.Type,
		Class: CLASS_NONE,
		Ttl:   0,
	})
	return b
}

// rrs are added
func (b MsgBuilder) UpdateAddRRset(rrset *RRset) MsgBuilder {
	b.AddRRset(AuthSection, rrset)
	return b
}

// delete rrs with specified name, type
func (b MsgBuilder) UpdateRemoveRRset(rrset *RRset) MsgBuilder {
	b.AddRRset(AuthSection, &RRset{
		Name:  rrset.Name,
		Type:  rrset.Type,
		Class: CLASS_ANY,
		Ttl:   0,
	})
	return b
}

// delete all rrset with name
func (b MsgBuilder) UpdateRemoveName(name *Name) MsgBuilder {
	b.AddRRset(AuthSection, &RRset{
		Name:  *name,
		Type:  RR_ANY,
		Class: CLASS_ANY,
		Ttl:   0,
	})
	return b
}

// Remove rr with specified rdata
func (b MsgBuilder) UpdateRemoveRdata(rrset *RRset) MsgBuilder {
	b.AddRRset(AuthSection, &RRset{
		Name:   rrset.Name,
		Type:   rrset.Type,
		Class:  CLASS_NONE,
		Ttl:    0,
		Rdatas: rrset.Rdatas,
	})
	return b
}
