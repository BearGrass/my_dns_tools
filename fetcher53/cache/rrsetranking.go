package cache

import (
	"gitlab.alibaba-inc.com/fengjin.hf/g53"
)

type TrustLevel int

const (
	AdditionalWithoutAA TrustLevel = 0
	AuthorityWithoutAA  TrustLevel = 1
	AdditionalWithAA    TrustLevel = 2
	AnswerWithoutAA     TrustLevel = 3
	AuthorityWithAA     TrustLevel = 4
	AnswerWithAA        TrustLevel = 5
)

/*
- The authoritative data included in the answer section of an
  authoritative reply.
- Data from the authority section of an authoritative answer,
  Glue from a primary zone,
- Data from the answer section of a non-authoritative answer, and
  non-authoritative data from the answer section of authoritative
  answers,
- Additional information from an authoritative answer,
  Data from the authority section of a non-authoritative answer,
  Additional information from non-authoritative answers.
*/

func getRRsetTrustLevel(msg *g53.Message, sec g53.SectionType) TrustLevel {
	aa := msg.Header.GetFlag(g53.FLAG_AA)
	switch sec {
	case g53.AnswerSection:
		if aa {
			return AnswerWithAA
		} else {
			return AnswerWithoutAA
		}
	case g53.AuthSection:
		if aa {
			return AuthorityWithAA
		} else {
			return AuthorityWithoutAA
		}
	case g53.AdditionalSection:
		if aa {
			return AdditionalWithAA
		} else {
			return AdditionalWithoutAA
		}
	default:
		panic("unknown section type")
	}
}
