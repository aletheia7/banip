package rbl

import (
	"net"
	"strings"

	"github.com/aletheia7/gogroup/v2"
	"github.com/aletheia7/sd/v6"
)

var j = sd.New()

type Search struct {
	gg   *gogroup.Group
	rbls []string
}

func New(gg *gogroup.Group, rbls []string) *Search {
	return &Search{
		gg:   gg,
		rbls: rbls,
	}
}

func (o *Search) Lookup(ip net.IP, just_first bool) (ret []string) {
	ip_rev := net.IP(make([]byte, len(ip.To4())))
	copy(ip_rev, ip.To4())
	for i, j := 0, len(ip_rev)-1; i < j; i, j = i+1, j-1 {
		ip_rev[i], ip_rev[j] = ip_rev[j], ip_rev[i]
	}
	if just_first {
		ret = make([]string, 0, 1)
	} else {
		ret = make([]string, 0, len(o.rbls))
	}
	for _, h := range o.rbls {
		select {
		case <-o.gg.Done():
			return
		default:
		}
		for try := 2; 0 < try; try-- {
			a, err := net.LookupHost(ip_rev.String() + "." + h)
			switch {
			case err == nil:
				try = 0
				if 0 < len(a) {
					ret = append(ret, h)
				}
				if just_first {
					return
				}
			case strings.HasSuffix(err.Error(), "i/o timeout"):
				j.Warning("i/o timeout:", ip.String(), h)
			case strings.HasSuffix(err.Error(), "no such host"):
				try = 0
			default:
				j.Warning(err)
			}
		}
	}
	return
}
