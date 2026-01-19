package g53

import (
	"bytes"
	"fmt"

	"gitlab.alibaba-inc.com/fengjin.hf/cement/buffer"
)

type SectionType int

const (
	AnswerSection     SectionType = 0
	AuthSection       SectionType = 1
	AdditionalSection SectionType = 2
)

const SectionCount = 3

type Section []*RRset

func (s Section) rrCount() int {
	count := 0
	for i := 0; i < len(s); i++ {
		rrCount := s[i].RRCount()
		//for empty rdata, just count as 1
		if rrCount == 0 {
			rrCount = 1
		}
		count += rrCount
	}
	return count
}

func (s Section) Rend(r *MsgRender) error {
	for i := 0; i < len(s); i++ {
		if err := s[i].Rend(r); err != nil {
			return err
		}
	}
	return nil
}

func (s Section) ToWire(buf *buffer.OutputBuffer) {
	for i := 0; i < len(s); i++ {
		s[i].ToWire(buf)
	}
}

func (s Section) String() string {
	var buf bytes.Buffer
	for i := 0; i < len(s); i++ {
		if s[i].Type != RR_OPT && s[i].Type != RR_TSIG {
			buf.WriteString(s[i].String())
		}
	}
	return buf.String()
}

func (s Section) Clear() Section {
	for i := range s {
		s[i] = nil
	}
	return s[:0]
}

type Message struct {
	noCopy

	Header   Header
	Question *Question
	question Question
	sections [SectionCount]Section
}

func MessageFromWire(buf *buffer.InputBuffer) (*Message, error) {
	m := Message{}
	if err := m.FromWire(buf); err != nil {
		return nil, err
	} else {
		return &m, nil
	}
}

func (m *Message) FromWire(buf *buffer.InputBuffer) error {
	if err := m.Header.FromWire(buf); err != nil {
		return err
	}

	if m.Header.QDCount == 1 {
		if err := m.question.FromWire(buf); err != nil {
			return err
		}
		m.Question = &m.question
	} else {
		m.Question = nil //in axfr message, question could be nil
	}

	for i := 0; i < SectionCount; i++ {
		if err := m.sectionFromWire(SectionType(i), buf); err != nil {
			return err
		}
	}

	return nil
}

func (m *Message) sectionFromWire(st SectionType, buf *buffer.InputBuffer) error {
	var s Section
	var count uint16
	switch st {
	case AnswerSection:
		count = m.Header.ANCount
		s = m.sections[0]
	case AuthSection:
		count = m.Header.NSCount
		s = m.sections[1]
	case AdditionalSection:
		count = m.Header.ARCount
		s = m.sections[2]
	}

	if count == 0 {
		return nil
	}

	var (
		lastRRset *RRset
	)
	for i := uint16(0); i < count; i++ {
		var rrset RRset
		if err := rrset.FromWire(buf); err != nil {
			return err
		}

		if rrset.Type == RR_OPT {
			if st != AdditionalSection {
				return fmt.Errorf("opt rr exist in non-addtional section")
			}
		} else if rrset.Type == RR_TSIG {
			if st != AdditionalSection {
				return fmt.Errorf("tsig rr exist in non-addtional section")
			} else if i != count-1 {
				return fmt.Errorf("tsig rr isn't the last rr")
			}
		}

		if lastRRset == nil {
			lastRRset = &rrset
			continue
		}

		if lastRRset.IsSameRRset(&rrset) {
			if rrset.Type == RR_TSIG {
				return fmt.Errorf("tsig should has only one rdata")
			}
			if len(rrset.Rdatas) == 0 {
				return fmt.Errorf("duplicate rrset with empty rdata")
			}
			lastRRset.Rdatas = append(lastRRset.Rdatas, rrset.Rdatas[0])
		} else {
			s = append(s, lastRRset)
			lastRRset = &rrset
		}
	}

	if lastRRset != nil {
		s = append(s, lastRRset)
	}
	m.sections[st] = s
	return nil
}

func (m *Message) GetEdns() (*EDNS, error) {
	additional := m.GetSection(AdditionalSection)
	c := len(additional)
	if c == 0 {
		return nil, nil
	}

	var optRRset *RRset
	switch additional[c-1].Type {
	case RR_OPT:
		optRRset = additional[c-1]
	case RR_TSIG:
		if c > 1 && additional[c-2].Type == RR_OPT {
			optRRset = additional[c-2]
		}
	}

	if optRRset == nil {
		return nil, nil
	}

	var edns EDNS
	if err := edns.FromRRset(optRRset); err != nil {
		return nil, err
	} else {
		return &edns, nil
	}
}

func (m *Message) GetTsig() (*Tsig, error) {
	additional := m.GetSection(AdditionalSection)
	c := len(additional)
	if c > 0 && additional[c-1].Type == RR_TSIG {
		return TsigFromRRset(additional[c-1])
	} else {
		return nil, nil
	}
}

//return if truncaated
func (m *Message) Rend(r *MsgRender) bool {
	(&m.Header).Rend(r)

	if m.Question != nil {
		m.Question.Rend(r)
	}

	pos := r.Len()
	for i := 0; i < SectionCount; i++ {
		if s := m.sections[i]; s != nil {
			if err := s.Rend(r); err != nil {
				m.truncate(r, pos)
				return true
			}
		}
	}
	return false
}

//only keep question, make all section empty
func (m *Message) truncate(r *MsgRender, pos int) {
	h := m.Header
	h.SetFlag(FLAG_TC, true)
	r.WriteUint16At(2, h.flag())
	//skip question section count
	r.WriteUint16At(6, 0)
	r.WriteUint16At(8, 0)
	r.WriteUint16At(10, 0)
	r.Truncate(pos)
}

func (m *Message) RendWithoutTsig(r *MsgRender) error {
	additional := m.GetSection(AdditionalSection)
	c := len(additional)
	if c > 0 && additional[c-1].Type == RR_TSIG {
		m.sections[AdditionalSection] = additional[:c-1]
		m.Header.ARCount -= 1
		if m.Rend(r) {
			return fmt.Errorf("message is too big")
		}
		m.Header.ARCount += 1
		m.sections[AdditionalSection] = additional
	}
	return nil
}

func (m *Message) ToWire(buf *buffer.OutputBuffer) {
	(&m.Header).ToWire(buf)
	if m.Question != nil {
		m.Question.ToWire(buf)
	}

	for i := 0; i < SectionCount; i++ {
		if s := m.sections[i]; s != nil {
			m.sections[i].ToWire(buf)
		}
	}
}

func (m *Message) String() string {
	var buf bytes.Buffer
	buf.WriteString(m.Header.String())
	buf.WriteByte('\n')

	if edns, _ := m.GetEdns(); edns != nil {
		buf.WriteString(";; OPT PSEUDOSECTION:\n")
		buf.WriteString(edns.String())
	}

	buf.WriteString(";; QUESTION SECTION:\n")
	if m.Question != nil {
		buf.WriteString(m.Question.String())
		buf.WriteByte('\n')
	}

	if len(m.sections[AnswerSection]) > 0 {
		buf.WriteString("\n;; ANSWER SECTION:\n")
		buf.WriteString(m.sections[AnswerSection].String())
	}

	if len(m.sections[AuthSection]) > 0 {
		buf.WriteString("\n;; AUTHORITY SECTION:\n")
		buf.WriteString(m.sections[AuthSection].String())
	}

	if len(m.sections[AdditionalSection]) > 0 {
		buf.WriteString("\n;; ADDITIONAL SECTION:\n")
		buf.WriteString(m.sections[AdditionalSection].String())
	}

	if tsig, _ := m.GetTsig(); tsig != nil {
		buf.WriteString("\n;; Tsig PSEUDOSECTION:\n")
		buf.WriteString(tsig.String())
	}

	return buf.String()
}

func (m *Message) GetSection(st SectionType) Section {
	return m.sections[st]
}

func (m *Message) Clear() {
	m.Header.Clear()
	m.Question = nil
	//this will reuse the backend array, this may cause
	//memory leak if there is a big section but after that
	//the section has very few rrset
	for i := 0; i < SectionCount; i++ {
		if s := m.sections[i]; s != nil {
			m.sections[i] = s.Clear()
		}
	}
}

func (m *Message) HasRRset(st SectionType, rrset *RRset) bool {
	return m.rrsetIndex(st, &rrset.Name, rrset.Type, rrset.Class) != -1
}

func (m *Message) SectionRRCount(st SectionType) int {
	if s := m.sections[st]; s != nil {
		return s.rrCount()
	} else {
		return 0
	}
}

func (m *Message) SectionRRsetCount(st SectionType) int {
	return len(m.sections[st])
}
