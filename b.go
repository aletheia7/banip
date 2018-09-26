// Copyright 2018 aletheia7. All rights reserved. Use of this source code is
// governed by a BSD-2-Clause license that can be found in the LICENSE file.

package main

import (
	"banip/filter"
	"banip/nft"
	br "banip/rbl"
	"banip/server"
	"flag"
	"fmt"
	"github.com/aletheia7/gogroup"
	"github.com/aletheia7/mbus"
	"github.com/aletheia7/sd"
	"gogitver"
	"net"
	"os/user"
	"strings"
)

var (
	testdata = flag.String("testdata", "", "run path to toml, use testdata and exit")
	test     = flag.String("test", "", "run path to toml, use journalctl and exit")
	test_nft = flag.Bool("testnft", false, "add banip")
	blip     = flag.String("blip", "", "blacklist IP and exit")
	wlip     = flag.String("wlip", "", "whitelist IP and exit")
	rmip     = flag.String("rmip", "", "remove IP and exit")
	qip      = flag.String("qip", "", "remove IP and exit")
	since    = flag.String("since", "", "passed to journalctl --since")
	rbl      = flag.String("rbl", "", "query rbls with IP and exit")
	rbls_in  = flag.String("rbls", "dnsbl-1.uceprotect.net,dnsbl-2.uceprotect.net,dnsbl-3.uceprotect.net,sbl-xbl.spamhaus.org,bl.spamcop.net,dnsbl.sorbs.net", "rbls: comma separted")
	rbls     []string
	nf_mode  = flag.Bool("nf", true, "blocks IP by rbl")
	device   = flag.String("device", "", "required netdev device; i.e. eth0, br0, enp2s0")
	load_f2b = flag.String("load-f2b", "", "load <full path>/fail2ban.sqlite3 and exit")
	ver      = flag.Bool("v", false, "version")
	j        = sd.New()
	gg       = gogroup.New(gogroup.Add_signals(gogroup.Unix))
)

const tsfmt = `2006-01-02 15:04:05-07:00`

func main() {
	flag.Parse()
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
	switch {
	case 0 < len(*rbl):
		j.Option(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
		go do_rbl()
	case 0 < len(*wlip):
		j.Option(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
		j.Info("wlip:", *wlip)
		ip := net.ParseIP(*wlip)
		if ip == nil {
			j.Err("invalid ip", ip)
			return
		}
		server.New(gg, u.HomeDir, rbls).Wl(ip)
		gg.Cancel()
		return
	case 0 < len(*blip):
		j.Option(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
		j.Info("blip:", *blip)
		ip := net.ParseIP(*wlip)
		if ip == nil {
			j.Err("invalid ip", ip)
			return
		}
		server.New(gg, u.HomeDir, rbls).Bl(ip)
		gg.Cancel()
		return
	case 0 < len(*rmip):
		j.Option(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
		j.Info("rmip:", *rmip)
		ip := net.ParseIP(*rmip)
		if ip == nil {
			j.Err("invalid ip", ip)
			return
		}
		server.New(gg, u.HomeDir, rbls).Rm(ip)
		gg.Cancel()
		return
	case 0 < len(*qip):
		j.Option(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
		j.Info("qip:", *qip)
		ip := net.ParseIP(*qip)
		if ip == nil {
			j.Err("invalid ip", ip)
			return
		}
		server.New(gg, u.HomeDir, rbls).Q(ip)
		gg.Cancel()
		return
	case *test_nft:
		j = sd.New(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
		if len(*device) == 0 {
			j.Err("missing device", *device)
			flag.PrintDefaults()
			return
		}
		t, err := nft.New_table(`inet`, `filter`, `banip`, *device)
		if err != nil {
			j.Err(err.Err)
			j.Err(string(err.Output))
			return
		}
		l := 10
		ip := make([]string, 0, l)
		for i := 1; i < l; i++ {
			ip = append(ip, fmt.Sprintf("127.99.0..%v", i))
		}
		t.Add_set(ip...)
		return
	case 0 < len(*load_f2b):
		j = sd.New(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
		j.Info("load fail2ban")
		go server.Load_fail2ban(gg, *load_f2b, u.HomeDir)
	case 0 < len(*test):
		j.Option(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
		j.Info("test:", *test)
		bus := mbus.New_bus(gg)
		if f, err := filter.New(gg, bus, *test, server.New(gg, u.HomeDir, rbls), rbls); err == nil {
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
		if f, err := filter.New(gg, bus, *testdata, server.New(gg, u.HomeDir, rbls), rbls); err == nil {
			f.Testdata()
		} else {
			j.Err(err)
			gg.Cancel()
			return
		}
	default:
		if len(*device) == 0 && !*nf_mode {
			j.Err("missing device", *device, *nf_mode)
			return
		}
		server.New(gg, u.HomeDir, rbls).Run(*device, *since, *nf_mode)
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
