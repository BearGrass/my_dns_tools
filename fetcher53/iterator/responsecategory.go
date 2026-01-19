package iterator

import (
	"fmt"

	"gitlab.alibaba-inc.com/fengjin.hf/fetcher53/logger"
	"gitlab.alibaba-inc.com/fengjin.hf/g53"
	"go.uber.org/zap"
)

type ResponseCategory uint8

const (
	Answer      ResponseCategory = 0
	CName       ResponseCategory = 1
	CNameAnswer ResponseCategory = 2
	NXDomain    ResponseCategory = 3
	NXRRset     ResponseCategory = 4
	Referral    ResponseCategory = 5
	ServerFail  ResponseCategory = 6
)

func (c ResponseCategory) String() string {
	switch c {
	case Answer:
		return "answer"
	case CName:
		return "cname"
	case CNameAnswer:
		return "cnameAnswer"
	case NXDomain:
		return "nxdomain"
	case NXRRset:
		return "nxrrset"
	case Referral:
		return "referral"
	case ServerFail:
		return "serverFail"
	default:
		panic("unreachable branch for responseCategory")
	}
}

func SanitizeClassifyResponse(zone, name *g53.Name, typ g53.RRType, resp *g53.Message) (ResponseCategory, error) {
	category, err := classifyResponse(zone, name, typ, resp)
	if err != nil {
		return category, err
	}

	switch category {
	case Answer, CName, CNameAnswer:
		sanitizeAuthSection(zone, resp)
		sanitizeAdditionalSection(zone, resp)
	case NXDomain, NXRRset:
		cleanAdditionalSection(resp)
	case Referral:
		sanitizeAdditionalSection(zone, resp)
	}
	return category, nil
}

func classifyResponse(zone, name *g53.Name, typ g53.RRType, resp *g53.Message) (ResponseCategory, error) {
	if resp.Question == nil {
		return ServerFail, fmt.Errorf("response has no question")
	}

	if !resp.Question.Name.Equals(name) || resp.Question.Type != typ {
		return ServerFail, fmt.Errorf("response question doesn't match query")
	}

	switch resp.Header.Rcode {
	case g53.R_NOERROR:
		if resp.Header.ANCount == 0 {
			return classifyNegativeResponse(zone, name, typ, resp)
		} else {
			return classifyPositiveResponse(zone, name, typ, resp)
		}
	case g53.R_NXDOMAIN:
		if resp.Header.ANCount == 0 {
			return NXDomain, nil
		} else {
			return classifyPositiveResponse(zone, name, typ, resp)
		}
	default:
		return ServerFail, nil
	}
}

func classifyPositiveResponse(zone, name *g53.Name, typ g53.RRType, resp *g53.Message) (ResponseCategory, error) {
	answerRRsets := resp.GetSection(g53.AnswerSection)
	if !answerRRsets[0].Name.Equals(name) {
		return ServerFail, fmt.Errorf("answer doesn't match question")
	}

	if answerRRsets[0].Type == typ {
		if len(answerRRsets) != 1 {
			return ServerFail, fmt.Errorf("extra rrset in answer section")
		}
		return Answer, nil
	} else if answerRRsets[0].Type == g53.RR_CNAME {
		return classifyCNameResponse(zone, name, typ, resp)
	} else {
		return ServerFail, fmt.Errorf("invalid rrset in answer section")
	}
}

func classifyNegativeResponse(zone, name *g53.Name, typ g53.RRType, resp *g53.Message) (ResponseCategory, error) {
	if resp.Header.NSCount == 0 {
		return ServerFail, fmt.Errorf("empty response")
	}
	authRRsets := resp.GetSection(g53.AuthSection)
	if len(authRRsets) != 1 {
		return ServerFail, fmt.Errorf("invalid auth section which should have one ns or one soa")
	}
	if authRRsets[0].Type == g53.RR_NS {
		return classifyReferralResponse(zone, name, typ, resp)
	} else if authRRsets[0].Type == g53.RR_SOA {
		if !authRRsets[0].Name.IsSubDomain(zone) {
			return ServerFail, fmt.Errorf("soa name %s isn't under the zone %s",
				authRRsets[0].Name.String(false),
				zone.String(false))
		}
		if len(authRRsets[0].Rdatas) != 1 {
			return ServerFail, fmt.Errorf("soa %s should has one rdata but get %d",
				authRRsets[0].Name.String(false),
				len(authRRsets[0].Rdatas))
		}
		return NXRRset, nil
	} else {
		return ServerFail, fmt.Errorf("invalid record type %s in auth section", authRRsets[0].Type.String())
	}
}

func classifyCNameResponse(zone, name *g53.Name, typ g53.RRType, resp *g53.Message) (ResponseCategory, error) {
	answerRRsets := resp.GetSection(g53.AnswerSection)
	lastName := name
	truncatePos := 0
	for i, answer := range answerRRsets {
		if !answer.Name.Equals(lastName) {
			if i == 0 {
				return ServerFail, fmt.Errorf("broken cname chain")
			} else {
				// Endure extra invalid data
				truncatePos = i
				break
			}
		}

		if !answer.Name.IsSubDomain(zone) {
			truncatePos = i
			break
		}

		if answer.Type == typ {
			if i == len(answerRRsets)-1 {
				return CNameAnswer, nil
			} else {
				return ServerFail, fmt.Errorf("answer has extra rrset")
			}
		}

		if answer.Type != g53.RR_CNAME {
			return ServerFail, fmt.Errorf("rrset in answer section should be either exact answer or cname record")
		}

		if answer.RRCount() != 1 {
			return ServerFail, fmt.Errorf("cname should has only one rdata")
		}

		lastName = answer.Rdatas[0].(*g53.CName).Name
	}

	if truncatePos != 0 {
		builder := g53.NewMsgBuilder(resp).ClearSection(g53.AnswerSection)
		for i := 0; i < truncatePos; i++ {
			builder.AddRRset(g53.AnswerSection, answerRRsets[i])
		}
		builder.Done()
	}
	return CName, nil
}

func classifyReferralResponse(zone, name *g53.Name, typ g53.RRType, resp *g53.Message) (ResponseCategory, error) {
	authRRsets := resp.GetSection(g53.AuthSection)
	if !authRRsets[0].Name.IsSubDomain(zone) {
		return ServerFail, fmt.Errorf("name ns record is out of zone")
	}

	if !name.IsSubDomain(&authRRsets[0].Name) {
		return ServerFail, fmt.Errorf("query name doesn't belong to referral zone")
	}

	return Referral, nil
}

func sanitizeAuthSection(zone *g53.Name, resp *g53.Message) {
	g53.NewMsgBuilder(resp).FilterRRset(g53.AuthSection, func(rrset *g53.RRset) bool {
		//host may also host sub domain
		return rrset.Name.IsSubDomain(zone) && rrset.Type == g53.RR_NS
	}).Done()
}

func sanitizeAdditionalSection(zone *g53.Name, resp *g53.Message) {
	g53.NewMsgBuilder(resp).FilterRRset(g53.AdditionalSection, func(rrset *g53.RRset) bool {
		return rrset.Name.IsSubDomain(zone) && (rrset.Type == g53.RR_A || rrset.Type == g53.RR_AAAA)
	}).Done()
}

func cleanAdditionalSection(resp *g53.Message) {
	additionalRRsets := resp.GetSection(g53.AdditionalSection)
	if len(additionalRRsets) > 0 {
		g53.NewMsgBuilder(resp).ClearSection(g53.AdditionalSection).Done()
	}
}

func classifyCachedResponse(resp *g53.Message) ResponseCategory {
	switch resp.Header.Rcode {
	case g53.R_NOERROR:
		if resp.Header.ANCount == 0 {
			return NXRRset
		} else {
			return Answer
		}
	case g53.R_NXDOMAIN:
		return NXDomain
	default:
		logger.GetLogger().Fatal("cached response is coruppted ", zap.String("resp", resp.String()))
		//to make compiler happy
		panic("")
	}
}
