// Copyright 2018 aletheia7. All rights reserved. Use of this source code is
// governed by a BSD-2-Clause license that can be found in the LICENSE file.

package main

import (
	"banip/filter"
	"banip/nft"
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
	// wlip     = flag.String("wlip", "", "whitelist IP and exit")
	// blip     = flag.String("blip", "", "blacklist IP and exit")
	// rmip     = flag.String("rmip", "", "remove IP and exit")
	// qip      = flag.String("qip", "", "query IP in datbase and exit")
	rbl      = flag.String("rbl", "", "query rbls with IP and exit")
	rbls_in  = flag.String("rbls", "sbl-xbl.spamhaus.org,bl.spamcop.net,dnsbl.sorbs.net,dnsbl-1.uceprotect.net,dnsbl-2.uceprotect.net,dnsbl-3.uceprotect.net", "rbls: comma separted")
	rbls     = []string{}
	device   = flag.String("device", "", "required netdev device; i.e. eth0, br0, enp2s0")
	load_f2b = flag.String("load-f2b", "", "load <full path>/fail2ban.sqlite3 and exit")
	ver      = flag.Bool("v", false, "version")
	j        = sd.New()
	gg       = gogroup.New(gogroup.Add_signals(gogroup.Unix))
)

const tsfmt = `2006-01-02 15:04:05-07:00`

func main() {
	flag.Parse()
	if *ver {
		j.Option(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
		j.Info(gogitver.Git())
		return
	}
	filter.Rbls = strings.Split(*rbls_in, ",")
	u, err := user.Current()
	if err != nil {
		j.Err(err)
		return
	}
	switch {
	case 0 < len(*rbl):
		j.Option(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
		go do_rbl()
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
		if f, err := filter.New(gg, bus, *test, server.New(gg, u.HomeDir, *device)); err == nil {
			go server.Journal(gg, f, true, f.Tag)
		} else {
			j.Err(err)
			gg.Cancel()
			return
		}
	case 0 < len(*testdata):
		j.Option(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
		j.Info("testdata:", *testdata)
		bus := mbus.New_bus(gg)
		if f, err := filter.New(gg, bus, *testdata, server.New(gg, u.HomeDir, *device)); err == nil {
			f.Testdata()
		} else {
			j.Err(err)
			gg.Cancel()
			return
		}
	default:
		if len(*device) == 0 {
			j.Err("missing device", *device)
			return
		}
		server.New(gg, u.HomeDir, *device).Run()
	}
	defer gg.Wait()
	<-gg.Done()
}

func do_rbl() {
	defer gg.Cancel()
	ip := net.ParseIP(*rbl)
	c := make(chan interface{}, len(rbls)+1)
	filter.Check_rbl(gg, ip, true, c)
	for {
		select {
		case <-gg.Done():
			return
		case r := <-c:
			switch t := r.(type) {
			case *filter.Rbl_result:
				j.Info(ip.String(), t.Rbl, t.Found)
			default:
				return
			}
		}
	}
}
