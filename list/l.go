package list

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type WB struct {
	W *W
	B *B
}

func New() *WB {
	return &WB{
		W: &W{
			net: map[*net.IPNet]bool{},
			ip:  map[string]bool{},
		},
		B: &B{
			ip: map[string]*time.Time{},
		},
	}
}

type W struct {
	mu  sync.RWMutex
	net map[*net.IPNet]bool
	ip  map[string]bool
}

func (o *W) Lookup(ip net.IP) (found bool) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if found = o.ip[ip2bin(ip)]; found {
		return
	}
	for ipnet := range o.net {
		if found = ipnet.Contains(ip); found {
			return
		}
	}
	return
}

// ip: net.IP or net.IPNet
func (o *W) Add(ip string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	v, err := Valid_ip_cidr(ip)
	if err != nil {
		return err
	}
	switch t := v.(type) {
	case *net.IP:
		o.ip[ip2bin(*t)] = true
	case *net.IPNet:
		o.net[t] = true
	}
	return nil
}

// Returns *net.IP | *net.IPNet, error
func Valid_ip_cidr(ip string) (interface{}, error) {
	v := net.ParseIP(ip)
	if v == nil {
		_, ipnet, err := net.ParseCIDR(ip)
		if err == nil {
			return ipnet, nil
		} else {
			return ``, err
		}
	} else {
		return &v, nil
	}
}

// ip: net.IP or net.IPNet
func (o *W) Remove(ip string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if v := net.ParseIP(ip); v == nil {
		if _, ipnet, err := net.ParseCIDR(ip); err == nil {
			delete(o.net, ipnet)
		}
	} else {
		delete(o.ip, ip2bin(v))
	}
	return
}

func (o *W) Len() int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return len(o.net) + len(o.ip)
}

type B struct {
	mu sync.RWMutex
	ip map[string]*time.Time
}

func (o *B) Lookup(ip net.IP) (found bool) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	_, found = o.ip[ip2bin(ip)]
	return
}

func (o *B) Lookup_all(ip net.IP) (ts *time.Time, found bool) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	ts, found = o.ip[ip2bin(ip)]
	return
}

func (o *B) Add(ip string, ts *time.Time) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	v := net.ParseIP(ip)
	if v == nil {
		return fmt.Errorf("invalid IP %v", ip)
	}
	o.ip[ip2bin(v)] = ts
	return nil
}

func (o *B) Remove(ip string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if v := net.ParseIP(ip); v == nil {
		return
	} else {
		delete(o.ip, ip2bin(net.ParseIP(ip)))
	}
}

func (o *B) Expire(dur time.Duration) (expired int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	ct := len(o.ip)
	now := time.Now()
	for ip, ts := range o.ip {
		if ts.Add(dur).Before(now) {
			delete(o.ip, ip)
		}
	}
	return ct - len(o.ip)
}

func (o *B) All() (a []string) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	a = make([]string, 0, len(o.ip))
	for ip := range o.ip {
		a = append(a, ip)
	}
	return
}

func (o *B) Len() int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return len(o.ip)
}

func ip2bin(ip net.IP) string {
	return string(ip.To4())
}
