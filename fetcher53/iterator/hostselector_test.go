package iterator

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	ut "gitlab.alibaba-inc.com/fengjin.hf/cement/unittest"
)

func TestHostSelector(t *testing.T) {
	selector := NewRTTBasedHostSelector(3)
	for i := 1; i < 4; i++ {
		selector.SetRTT(net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", i, i, i, i)), 1*time.Second)
	}
	//following hosts will overwrite first 3 hosts
	host1 := net.ParseIP("4.4.4.4")
	host2 := net.ParseIP("5.5.5.5")
	host3 := net.ParseIP("6.6.6.6")
	selector.SetRTT(host1, 10*time.Second)
	selector.SetRTT(host2, 11*time.Second)
	selector.SetRTT(host3, 12*time.Second)
	target := selector.Select([]Host{host1, host2})
	ut.Equal(t, target.String(), "4.4.4.4")

	selector.SetRTT(host1, 14*time.Second)
	target = selector.Select([]Host{host1, host2})
	ut.Equal(t, target.String(), "5.5.5.5")

	for i := 0; i < MaxTimeoutCount; i++ {
		selector.SetTimeout(host1, time.Minute)
		selector.SetTimeout(host2, time.Minute)
		selector.SetTimeout(host3, time.Minute)
	}
	target = selector.Select([]Host{host1, host2})
	ut.Assert(t, target == nil, "")

	selector.SetRTT(host2, 2*time.Second)
	target = selector.Select([]Host{host1, host2})
	ut.Equal(t, target.String(), "5.5.5.5")

	host4 := net.ParseIP("1.1.1.1")
	target = selector.Select([]Host{host1, host2, host4})
	ut.Equal(t, target.String(), "1.1.1.1")
}

func TestHostSelectorDataRace(t *testing.T) {
	selector := NewRTTBasedHostSelector(20)

	var wg sync.WaitGroup
	writerCount := 5
	addrCount := 100
	wg.Add(writerCount)
	for i := 0; i < writerCount; i++ {
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				seg := 1 + rand.Intn(addrCount-1)
				selector.SetRTT(net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", seg, seg, seg, seg)),
					time.Duration(i)*time.Second)
				<-time.After(time.Duration(rand.Intn(20)) * time.Millisecond)
			}
		}()
	}

	readerCount := 15
	wg.Add(readerCount)
	for i := 0; i < readerCount; i++ {
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				addrCount := 1 + rand.Intn(5)
				hosts := make([]Host, 0, addrCount)
				for j := 0; j < addrCount; j++ {
					seg := 1 + rand.Intn(50)
					hosts = append(hosts, net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", seg, seg, seg, seg)))
				}
				selector.Select(hosts)
				<-time.After(time.Duration(10+rand.Intn(20)) * time.Millisecond)
			}
		}()
	}

	wg.Wait()
	hosts := make([]Host, 0, addrCount)
	for i := 0; i < addrCount; i++ {
		hosts = append(hosts, net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", i+1, i+1, i+1, i+1)))
	}
	target := selector.Select(hosts)
	ut.Assert(t, target != nil, "")
}
