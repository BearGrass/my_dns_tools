package util

import (
	"net"
	"testing"

	ut "gitlab.alibaba-inc.com/fengjin.hf/cement/unittest"
	"gitlab.alibaba-inc.com/fengjin.hf/g53"
)

func hashQuery(ip, name, typ string) uint64 {
	t, _ := g53.TypeFromString(typ)
	return HashQueryToHost(net.ParseIP(ip), g53.NameFromStringUnsafe(name), t)
}

func TestHash(t *testing.T) {
	ut.Equal(t, hashQuery("1.1.1.1", "a.com", "A"), hashQuery("1.1.1.1", "a.com", "A"))
	ut.Equal(t, hashQuery("1.1.1.1", "A.com", "A"), hashQuery("1.1.1.1", "a.com", "A"))
	ut.Equal(t, hashQuery("1.1.1.1", "A.com", "a"), hashQuery("1.1.1.1", "a.com", "A"))

	ut.Assert(t, hashQuery("1.1.1.1", "a.com", "A") != hashQuery("1.1.1.2", "a.com", "A"), "")
	ut.Assert(t, hashQuery("1.1.1.1", "a.com", "A") != hashQuery("1.1.1.1", "b.com", "A"), "")
	ut.Assert(t, hashQuery("1.1.1.1", "a.com", "a") != hashQuery("1.1.1.1", "a.com", "aaaa"), "")
}
