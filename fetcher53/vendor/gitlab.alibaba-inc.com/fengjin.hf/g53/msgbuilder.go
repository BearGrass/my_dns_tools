package g53

import (
	"gitlab.alibaba-inc.com/fengjin.hf/g53/util"
)

type MsgBuilder struct {
	msg *Message
}

func NewRequestBuilder(name *Name, typ RRType) MsgBuilder {
	q := &Question{
		Name:  *name,
		Type:  typ,
		Class: CLASS_IN,
	}

	return NewMsgBuilder(&Message{}).
		SetHeaderFlag(FLAG_RD, true).
		SetOpcode(OP_QUERY).
		SetRcode(R_NOERROR).
		SetId(util.GenMessageId()).
		SetQuestion(q)
}

func NewResponseBuilder(req *Message) MsgBuilder {
	if req.Question == nil {
		panic("request has no question")
	}

	return NewMsgBuilder(&Message{}).SetId(req.Header.Id).
		SetHeaderFlag(FLAG_QR, true).
		SetHeaderFlag(FLAG_RD, req.Header.GetFlag(FLAG_RD)).
		SetOpcode(req.Header.Opcode).
		SetRcode(R_NOERROR).
		SetQuestion(req.Question)
}

func NewMsgBuilder(msg *Message) MsgBuilder {
	return MsgBuilder{msg}
}

func (b MsgBuilder) SetQuestion(q *Question) MsgBuilder {
	b.msg.question = q.Clone()
	b.msg.Question = &b.msg.question
	return b
}

func (b MsgBuilder) SetHeaderFlag(f FlagField, set bool) MsgBuilder {
	b.msg.Header.SetFlag(f, set)
	return b
}

func (b MsgBuilder) SetOpcode(o Opcode) MsgBuilder {
	b.msg.Header.Opcode = o
	return b
}

func (b MsgBuilder) SetRcode(r Rcode) MsgBuilder {
	b.msg.Header.Rcode = r
	return b
}

func (b MsgBuilder) SetId(id uint16) MsgBuilder {
	b.msg.Header.Id = id
	return b
}

func (b MsgBuilder) ResizeSection(st SectionType, count int) MsgBuilder {
	if count > 0 {
		b.msg.sections[st] = make([]*RRset, 0, count)
	}
	return b
}

func (b MsgBuilder) AddRRset(st SectionType, rrset *RRset) MsgBuilder {
	if rrset.Type == RR_OPT || rrset.Type == RR_TSIG {
		panic("opt and rrsig cann't be set directly")
	}

	b.msg.sections[st] = append(b.msg.sections[st], rrset)
	return b
}

func (b MsgBuilder) SetEdns(edns *EDNS) MsgBuilder {
	s := b.msg.sections[AdditionalSection]
	b.msg.sections[AdditionalSection] = append(s, edns.ToRRset())
	return b
}

func (b MsgBuilder) AddRR(st SectionType, name *Name, typ RRType, class RRClass, ttl RRTTL, rdata Rdata, merge bool) MsgBuilder {
	msg := b.msg
	if merge {
		if typ == RR_OPT || typ == RR_TSIG {
			panic("opt and tsig rrset doesn't support merge")
		}

		if i := msg.rrsetIndex(st, name, typ, class); i != -1 {
			msg.sections[st][i].AddRdata(rdata)
			msg.sections[st][i].Ttl = ttl
			return b
		}
	}

	return b.AddRRset(st, &RRset{
		Name:   name.Clone(),
		Type:   typ,
		Class:  class,
		Ttl:    ttl,
		Rdatas: []Rdata{rdata},
	})
}

func (m *Message) rrsetIndex(st SectionType, name *Name, typ RRType, class RRClass) int {
	s := m.sections[st]
	for i := 0; i < len(s); i++ {
		if s[i].Class == class &&
			s[i].Type == typ &&
			s[i].Name.Equals(name) {
			return i
		}
	}
	return -1
}

func (b MsgBuilder) Done() *Message {
	b.msg.recalculateSectionRRCount()
	return b.msg
}

func (m *Message) recalculateSectionRRCount() {
	if m.Question == nil {
		m.Header.QDCount = 0
	} else {
		m.Header.QDCount = 1
	}

	m.Header.ANCount = uint16(m.SectionRRCount(AnswerSection))
	m.Header.NSCount = uint16(m.SectionRRCount(AuthSection))
	m.Header.ARCount = uint16(m.SectionRRCount(AdditionalSection))
}

func (b MsgBuilder) ClearSection(st SectionType) MsgBuilder {
	b.msg.clearSection(st)
	return b
}

func (m *Message) clearSection(st SectionType) {
	m.sections[st] = nil
	switch st {
	case AnswerSection:
		m.Header.ANCount = 0
	case AuthSection:
		m.Header.NSCount = 0
	case AdditionalSection:
		m.Header.ARCount = 0
	default:
		panic("question section couldn't be cleared")
	}
}

//this will modify rrset order
func (b MsgBuilder) FilterRRset(st SectionType, f func(*RRset) bool) MsgBuilder {
	rrsets := b.msg.GetSection(st)
	l := len(rrsets)
	for i := 0; i < l; {
		if !f(rrsets[i]) {
			if i != l-1 {
				rrsets[i] = rrsets[l-1]
			}
			l -= 1
			rrsets[l] = nil
		} else {
			i += 1
		}
	}

	if l != len(rrsets) {
		b.msg.sections[st] = rrsets[:l]
	}
	return b
}
