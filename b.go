// Copyright 2018 aletheia7. All rights reserved. Use of this source code is
// governed by a BSD-2-Clause license that can be found in the LICENSE file.

package main

import (
	"banip/filter"
	br "banip/rbl"
	"banip/server"
	"banip/syn"
	"flag"
	"github.com/aletheia7/gogroup"
	"github.com/aletheia7/mbus"
	"github.com/aletheia7/sd"
	"gogitver"
	"net"
	"os"
	"os/user"
	"strings"
)

var (
	testdata = flag.String("testdata", "", "run path to toml, use testdata and exit")
	test     = flag.String("test", "", "run path to toml, use journalctl and exit")
	blip     = flag.String("blip", "", "blacklist IP and exit")
	wlip     = flag.String("wlip", "", "whitelist IP/CIDR and exit")
	rmip     = flag.String("rmip", "", "remove IP and exit")
	qip      = flag.String("qip", "", "remove IP and exit")
	since    = flag.String("since", "", "passed to journalctl --since")
	rbl      = flag.String("rbl", "", "query rbls with IP and exit")
	rbls_in  = flag.String("rbls", "dnsbl-1.uceprotect.net,dnsbl-2.uceprotect.net,dnsbl-3.uceprotect.net,sbl-xbl.spamhaus.org,bl.spamcop.net,dnsbl.sorbs.net", "rbls: comma separted, or set banip_rbls environment variable")
	rbls     []string
	nf_mode  = flag.Bool("nf", false, "mode, blocks IP by rbl")
	syn_mode = flag.Bool("syn", false, "mode, blocks IP by sync-recv")
	load_f2b = flag.String("load-f2b", "", "load <full path>/fail2ban.sqlite3 and exit")
	ver      = flag.Bool("v", false, "version")
	j        = sd.New()
	gg       = gogroup.New(gogroup.Add_signals(gogroup.Unix))
)

const tsfmt = `2006-01-02 15:04:05-07:00`

func main() {
	flag.Parse()
	if s := os.Getenv("banip_rbls"); 0 < len(s) {
		*rbls_in = s
	}
	rbls = strings.Split(*rbls_in, ",")
	if *ver {
		j.Option(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
		j.Info(gogitver.Git())
		return
	}
	u, err := user.Current()
	if err != nil {
		j.Err(err)
		return
	}
	var srv *server.Server
	switch {
	case 0 < len(*rbl):
		j.Option(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
		go do_rbl()
	case 0 < len(*wlip):
		j.Option(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
		j.Info("wlip:", *wlip)
		server.New(gg, u.HomeDir, rbls).Wl(*wlip)
		gg.Cancel()
		return
	case 0 < len(*blip):
		j.Option(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
		j.Info("blip:", *blip)
		server.New(gg, u.HomeDir, rbls).Bl(*blip, "blip", nil, nil)
		gg.Cancel()
		return
	case 0 < len(*rmip):
		j.Option(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
		j.Info("rmip:", *rmip)
		server.New(gg, u.HomeDir, rbls).Rm(*rmip)
		gg.Cancel()
		return
	case 0 < len(*qip):
		j.Option(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
		j.Info("qip:", *qip)
		server.New(gg, u.HomeDir, rbls).Q(*qip)
		gg.Cancel()
		return
	case 0 < len(*load_f2b):
		j = sd.New(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
		j.Info("load fail2ban")
		go server.Load_fail2ban(gg, *load_f2b, u.HomeDir)
	case 0 < len(*test):
		j.Option(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
		j.Info("test:", *test)
		bus := mbus.New_bus(gg)
		if f, err := filter.New(gg, bus, *test, server.New(gg, u.HomeDir, rbls).WB(), rbls); err == nil {
			go server.Journal(gg, bus, true, f.Tag, *since)
		} else {
			j.Err(err)
			gg.Cancel()
			return
		}
	case 0 < len(*testdata):
		j.Option(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
		j.Info("testdata:", *testdata)
		bus := mbus.New_bus(gg)
		if f, err := filter.New(gg, bus, *testdata, server.New(gg, u.HomeDir, rbls).WB(), rbls); err == nil {
			f.Testdata()
		} else {
			j.Err(err)
			gg.Cancel()
			return
		}
	case *syn_mode:
		if srv == nil {
			srv = server.New(gg, u.HomeDir, rbls)
		}
		syn.New(gg, srv)
	case *nf_mode:
		if srv == nil {
			srv = server.New(gg, u.HomeDir, rbls)
		}
		j.Info("version:", gogitver.Git())
		srv.Run(*since, *nf_mode)
	default:
		j.Err("choose a mode")
		gg.Cancel()
	}
	defer gg.Wait()
	<-gg.Done()
}

func do_rbl() {
	defer gg.Cancel()
	for _, s := range (br.New(gg, rbls)).Lookup(net.ParseIP(*rbl), false) {
		j.Info(s)
	}
}
