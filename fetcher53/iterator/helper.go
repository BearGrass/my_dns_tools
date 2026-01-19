package iterator

import (
	"gitlab.alibaba-inc.com/fengjin.hf/g53"
)

// Only cache negative answer with SOA in auth section
func IsNegativeAnswerCacheable(resp *g53.Message) bool {
	additionals := resp.GetSection(g53.AuthSection)
	return len(additionals) == 1 && additionals[0].Type == g53.RR_SOA
}
