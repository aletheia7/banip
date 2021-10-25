package syn

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/aletheia7/banip/server"
	"github.com/aletheia7/gogroup/v2"
	"github.com/aletheia7/sd/v6"
)

var (
	j       = sd.New()
	max_syn = flag.Int("syn-max", 10, "max syn")
	syn_in  = flag.String("syn-src", "ss", "input: ss or <file name>")
)

const expire_sent = time.Hour

type Server struct {
	gg         *gogroup.Group
	args       []string
	out        bytes.Buffer
	addr       []string
	sent_mu    sync.Mutex
	sent_to_bl map[string]time.Time
	srv        *server.Server
}

func New(gg *gogroup.Group, srv *server.Server) {
	r := &Server{
		gg:         gg,
		addr:       make([]string, 0, 4),
		sent_to_bl: map[string]time.Time{},
		srv:        srv,
	}
	switch {
	case *syn_in == "ss":
		r.args = []string{"ss", "-t4naH", "-o", "state", "syn-recv"}
	default:
		r.args = []string{"cat", *syn_in}
	}
	doerr := func(err error) {
		j.Err(err)
		gg.Cancel()
	}
	infs, err := net.Interfaces()
	if err != nil {
		doerr(err)
		return
	}
	for _, in := range infs {
		a, err := in.Addrs()
		if err != nil {
			doerr(err)
			return
		}
		for _, addr := range a {
			ip, _, _ := net.ParseCIDR(addr.String())
			if ip == nil {
				doerr(fmt.Errorf("cannot parse ip: %v %v", addr.String(), err))
				return
			}
			if ip.IsLoopback() {
				continue
			}
			r.addr = append(r.addr, ip.String())
		}
	}
	go r.run()
	go r.expire()
}

func (o *Server) expire() {
	key := o.gg.Register()
	defer o.gg.Unregister(key)
	ticker := time.NewTicker(time.Minute * 10)
	defer ticker.Stop()
	for {
		select {
		case <-o.gg.Done():
			return
		case <-ticker.C:
			now := time.Now()
			o.sent_mu.Lock()
			for ip, ts := range o.sent_to_bl {
				if ts.Add(expire_sent).Before(now) {
					delete(o.sent_to_bl, ip)
				}
			}
			o.sent_mu.Unlock()
		}
	}
}

func (o *Server) run() {
	key := o.gg.Register()
	defer o.gg.Unregister(key)
	j.Info("mode: syn")
	if o.parse() != nil {
		return
	}
	for {
		select {
		case <-o.gg.Done():
			return
		case <-time.After(time.Second):
			if o.parse() != nil {
				return
			}
		}
	}
}

type sc struct {
	sent *time.Time
	ct   int
}

func (o *Server) parse() (err error) {
	o.out.Reset()
	cmd := exec.CommandContext(o.gg, o.args[0], o.args[1:]...)
	cmd.Stdout = &o.out
	err = cmd.Run()
	if err != nil {
		j.Err(cmd.Args, err)
		return
	}
	ip := map[string]*sc{}
line_loop:
	for _, line := range bytes.Split(o.out.Bytes(), []byte{10}) {
		if len(line) == 0 {
			continue
		}
		a := bytes.Fields(line)
		remote_ip, _, err := net.SplitHostPort(string(a[3]))
		if err != nil {
			j.Err(err)
			return err
		}
		for _, a := range o.addr {
			if remote_ip == a {
				continue line_loop
			}
		}
		remote_ipb := net.ParseIP(remote_ip)
		if o.srv.WB().W.Lookup(remote_ipb.To4()) {
			continue line_loop
		}
		st, ok := ip[remote_ip]
		if ok {
			st.ct++
		} else {
			st = &sc{}
			ip[remote_ip] = st
		}
		if st.sent == nil && *max_syn <= st.ct+1 {
			o.sent_mu.Lock()
			if _, ok := o.sent_to_bl[remote_ip]; ok {
				o.sent_mu.Unlock()
				continue
			}
			o.sent_to_bl[remote_ip] = time.Now()
			o.sent_mu.Unlock()
			// todo uncomment
			// id := o.srv.Bl(remote_ip, `syn ban`, nil, nil)
			j.Info("syn ban", remote_ip)
		}
	}
	return
}
