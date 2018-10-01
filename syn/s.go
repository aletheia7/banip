package syn

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/aletheia7/gogroup"
	"github.com/aletheia7/sd"
	"net"
	"os/exec"
	"time"
)

var (
	j       = sd.New()
	max_syn = flag.Int("syn-max", 10, "max syn")
	syn_in  = flag.String("syn-src", "ss", "input: ss or <file name>")
)

type Server struct {
	gg   *gogroup.Group
	args []string
	out  bytes.Buffer
	addr []net.IP
}

func New(gg *gogroup.Group) {
	r := &Server{
		gg:   gg,
		addr: make([]net.IP, 0, 4),
	}
	switch {
	case *syn_in == "ss":
		j.Info("syn-src", *syn_in)
		r.args = []string{"ss", "-t4naH", "-o", "state", "syn-recv"}
	default:
		j.Info("syn-src:", *syn_in)
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
			ip, _, err := net.ParseCIDR(addr.String())
			if ip == nil {
				doerr(fmt.Errorf("cannot parse ip: %v %v", addr.String(), err))
				return
			}
			if ip.IsLoopback() {
				continue
			}
			r.addr = append(r.addr, ip)
		}
	}
	j.Info(r.addr)
	go r.run()
}

func (o *Server) run() {
	key := o.gg.Register()
	defer o.gg.Unregister(key)
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
	sent bool
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
	// ip := map[string]*sc{}
	for _, line := range bytes.Split(o.out.Bytes(), []byte{10}) {
		if len(line) == 0 {
			continue
		}
		// j.Infof("%v %s", len(line), line)
		a := bytes.Fields(line)
		j.Infof("%s %s\n", a[2], a[3])

		// st, ok := ip[t]
		// if !ok {
		// 	ip[t] = &sc{ct: 1}
		// 	continue
		// }
		// st.ct++
	}
	// if !st.sent && *max_syn <= st.ct {
	// 	st.sent = true
	// 	j.Info("ban", t)
	// }
	return
}
