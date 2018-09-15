// Copyright 2018 aletheia7. All rights reserved. Use of this source code is
// governed by a BSD-2-Clause license that can be found in the LICENSE file.

package main

import (
	"banip/filter"
	"banip/nft"
	"bufio"
	"bytes"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/aletheia7/gogroup"
	"github.com/aletheia7/mbus"
	"github.com/aletheia7/sd"
	_ "github.com/mattn/go-sqlite3"
	"gogitver"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

var (
	testdata = flag.String("testdata", "", "run path to toml, use testdata and exit")
	test     = flag.String("test", "", "run path to toml, use journalctl and exit")
	test_nft = flag.Bool("testnft", false, "add banip")
	wlip     = flag.String("wlip", "", "whitelist IP and exit")
	blip     = flag.String("blip", "", "blacklist IP and exit")
	rmip     = flag.String("rmip", "", "remove IP and exit")
	qip      = flag.String("qip", "", "query IP in datbase and exit")
	rbl      = flag.String("rbl", "", "query rbls with IP and exit")
	rbls_in  = flag.String("rbls", "sbl-xbl.spamhaus.org,bl.spamcop.net,dnsbl.sorbs.net,dnsbl-1.uceprotect.net,dnsbl-2.uceprotect.net,dnsbl-3.uceprotect.net", "rbls: comma separted")
	rbls     = []string{}
	device   = flag.String("device", "", "required netdev device; i.e. eth0, br0, enp2s0")
	sqlite   = flag.String("sqlite", "banip.sqlite", "if not exist: will be made")
	toml_dir = flag.String("toml", "", "toml directory, default: <user home>/toml")
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
	rbls = strings.Split(*rbls_in, ",")
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
		t, err := nft.New_table(`netdev`, `filter`, `banip`, *device)
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
		go load_fail2ban(u.HomeDir)
	case 0 < len(*test):
		j.Option(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
		j.Info("test:", *test)
		bus := mbus.New_bus(gg)
		if f, err := filter.New(gg, bus, *test); err == nil {
			go journal(bus, true, f.Tag)
		} else {
			j.Err(err)
			gg.Cancel()
			return
		}
	case 0 < len(*testdata):
		j.Option(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
		j.Info("testdata:", *testdata)
		bus := mbus.New_bus(gg)
		if f, err := filter.New(gg, bus, *testdata); err == nil {
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
		go server(u.HomeDir)
	}
	defer gg.Wait()
	<-gg.Done()
}

func server(home string) {
	key := gg.Register()
	defer gg.Unregister(key)
	db := get_database(home)
	if db == nil {
		return
	}
	// 4 byte string key
	list := map[string]bool{}
	rows, err := db.QueryContext(gg, "select ip, ban from ip order by ip")
	if err != nil {
		j.Err(err)
		return
	}
	var ip string
	var ban int
	bl := make([]string, 0, 1000)
	wl_ct := 0
	for rows.Next() {
		if err = rows.Scan(&ip, &ban); err != nil {
			j.Err(err)
			return
		}
		if ban == 0 {
			wl_ct++
			list[string(net.ParseIP(ip).To4())] = false
		} else {
			bl = append(bl, ip)
			list[string(net.ParseIP(ip).To4())] = true
		}
	}
	if err = rows.Err(); err != nil {
		j.Err(err)
		return
	}
	j.Info("whitelist:", wl_ct)
	j.Info("blacklist:", len(bl))
	bset, e := nft.New_table(`netdev`, `filter`, `banip`, *device)
	if e != nil {
		j.Err(e)
		return
	}
	if 0 < len(bl) {
		bset.Add_set(bl...)
	}
	bl = nil
	bus := mbus.New_bus(gg)
	c := make(chan *mbus.Msg, 256)
	bus.Subscribe(c, filter.T_bl)
	defer bus.Unsubscribe(c, filter.T_bl)
	run_filter(bus, home)
	for {
		select {
		case <-gg.Done():
			return
		case in := <-c:
			switch in.Topic {
			case filter.T_bl:
				if a, ok := in.Data.(*filter.Action); ok {
					ip := net.ParseIP(a.Ip).To4()
					ip_bin := string(ip)
					if _, found := list[ip_bin]; !found {
						list[ip_bin] = true
						if err := bset.Add_set(a.Ip); err != nil {
							j.Err(err)
							return
						}
						j.Info("blacklist:", a.Ip)
						var rbl_found interface{} = nil
						if a.Check_rbl {
							c := make(chan interface{}, 2)
							check_rbl(ip, false, c)
							select {
							case <-gg.Done():
								return
							case r := <-c:
								switch t := r.(type) {
								case *rbl_result:
									if t.Found {
										rbl_found = t.Rbl
									}
								default:
									return
								}
							}
						}
						if _, err := db.ExecContext(gg, "insert or ignore into ip(ip, ban, ts, toml, rbl, log) values(:ip, 1, :ts, :toml, :rbl, :log)", sql.Named("ip", a.Ip), sql.Named("ts", time.Now().Format(tsfmt)), sql.Named("toml", a.Toml), sql.Named("rbl", rbl_found), sql.Named("log", a.Msg)); err != nil {
							j.Err(err)
							return
						}
					}
				}
			}
		}
	}
}

func run_filter(bus *mbus.Bus, home string) {
	td := filepath.Join(home, "toml", "*.toml")
	if 0 < len(*toml_dir) {
		td = filepath.Join(*toml_dir, "*.toml")
	}
	j.Info("toml:", td)
	toml, err := filepath.Glob(td)
	if err != nil {
		j.Err(err)
		return
	}
	tag := map[string]bool{}
	for _, p := range toml {
		f, err := filter.New(gg, bus, p)
		if err != nil {
			j.Err(err)
			return
		}
		if !f.Enabled {
			f.Stop()
			continue
		}
		for _, t := range f.Tag {
			tag[t] = true
		}
	}
	a := make([]string, 0, len(tag))
	for s := range tag {
		a = append(a, s)
	}
	journal(bus, false, a)
}

func get_database(home string) *sql.DB {
	db, err := sql.Open("sqlite3", "file://"+home+"/"+*sqlite+"?"+strings.Join([]string{"_journal=wal", "_fk=1", "_timeout=30000"}, `&`))
	if err != nil {
		j.Err(err)
		return nil
	}
	var ct int64
	err = db.QueryRowContext(gg, "select count(*) ct from sqlite_master where tbl_name='ip'").Scan(&ct)
	switch err {
	case nil:
		if ct == 0 {
			j.Info("making database")
			if _, err := db.ExecContext(gg, schema); err != nil {
				j.Err(err)
				return nil
			}
		}
	default:
		if err != nil {
			j.Err(err)
			return nil
		}
	}
	return db
}

var schema = `drop table if exists ip;
create table if not exists ip (
    ip text not null
  , ban int not null check(ban in (0, 1))
  , ts datetime not null
  , toml text
  , rbl text
  , log text
);
drop index if exists ip_i;
create unique index ip_i on ip(ip, ban);
-- vim: ts=2 expandtab`

func load_fail2ban(home string) {
	defer gg.Cancel()
	if _, err := os.Stat(*load_f2b); err != nil {
		j.Err(err)
		return
	}
	fdb, err := sql.Open("sqlite3", "file://"+*load_f2b+"?"+strings.Join([]string{"_journal=wal", "_fk=1", "_timeout=30000"}, `&`))
	if err != nil {
		j.Err(err)
		return
	}
	var jail string
	var ip string
	var ts time.Time
	in, err := fdb.QueryContext(gg, "select jail, ip, max(timeofban) ts from bans group by jail, ip order by ip")
	if err != nil {
		j.Err(err)
		return
	}
	defer fdb.Close()
	db := get_database(home)
	if db == nil {
		return
	}
	defer db.Close()
	opt := &sql.TxOptions{Isolation: sql.LevelSnapshot}
	tx, err := db.BeginTx(gg, opt)
	if err != nil {
		j.Err(err)
		return
	}
	insert, err := db.PrepareContext(gg, "insert or ignore into ip(ip, ban, ts, toml) values(:ip, 1, :ts, :toml)")
	if err != nil {
		j.Err(err)
	}
	ct := 0
	for in.Next() {
		if err = in.Scan(&jail, &ip, (*Stime)(&ts)); err != nil {
			j.Err(err)
			return
		}
		_, err := tx.StmtContext(gg, insert).ExecContext(gg, sql.Named("ip", ip), sql.Named("ts", ts.UTC().Format(tsfmt)), sql.Named("toml", "f2b"+jail))
		if err != nil {
			j.Err(err)
			return
		}
		ct++
	}
	if err = in.Err(); err != nil {
		j.Err(err)
		tx.Rollback()
		return
	}
	if err = tx.Commit(); err != nil {
		j.Err(err)
		return
	}
	j.Info("jails:", ct)
}

type m struct {
	Tag     string `json:"SYSLOG_IDENTIFIER"`
	Message string `json:"MESSAGE"`
}

func journal(bus *mbus.Bus, test bool, tag []string) {
	var tag_args []string
	if test {
		tag_args = make([]string, 0, (len(tag)*2)+2)
		tag_args = append(tag_args, "--output", "json")
	} else {
		tag_args = make([]string, 0, (len(tag)*2)+3)
		tag_args = append(tag_args, "-f", "--output", "json")
	}
	for _, t := range tag {
		tag_args = append(tag_args, "-t", t)
	}
	cmd := exec.CommandContext(gg, "journalctl", tag_args...)
	var e bytes.Buffer
	rp, wp := io.Pipe()
	cmd.Stdout = wp
	cmd.Stderr = &e
	if err := cmd.Start(); err != nil {
		j.Err(err)
		return
	}
	go func() {
		if test {
			defer func() {
				bus.Pub(filter.T_test, nil)
			}()
		}
		defer rp.Close()
		scanner := bufio.NewScanner(rp)
		for scanner.Scan() {
			var m m
			if err := json.NewDecoder(bytes.NewReader(scanner.Bytes())).Decode(&m); err != nil {
				j.Err(err, scanner.Text())
				continue
			}
			if test {
				bus.Pub(filter.T_test, m.Message)
			} else {
				bus.Pub(m.Tag, m.Message)
			}
		}
		if err := scanner.Err(); err != nil {
			j.Err(err)
		}
	}()
	go func() {
		defer wp.Close()
		if err := cmd.Wait(); err != nil {
			select {
			case <-gg.Done():
				return
			default:
				j.Err(err, e.String())
			}
		}
	}()
	return
}

func check_rbl(ip net.IP, all bool, out chan interface{}) {
	go func() {
		defer func() {
			out <- nil
		}()
		ip_rev := net.IP(make([]byte, len(ip.To4())))
		copy(ip_rev, ip.To4())
		for i, j := 0, len(ip_rev)-1; i < j; i, j = i+1, j-1 {
			ip_rev[i], ip_rev[j] = ip_rev[j], ip_rev[i]
		}
		for _, h := range rbls {
			select {
			case <-gg.Done():
				return
			default:
			}
			a, err := net.LookupHost(ip_rev.String() + "." + h)
			if err == nil {
				if 0 < len(a) {
					out <- &rbl_result{Rbl: h, Found: true}
					if !all {
						return
					}
				}
			} else {
				if strings.HasSuffix(err.Error(), "no such host") {
					out <- &rbl_result{Rbl: h}
					if !all {
						return
					}
				} else {
					j.Err(err)
					continue
				}
			}
		}
	}()
}

type rbl_result struct {
	Rbl   string
	Found bool
}

func do_rbl() {
	defer gg.Cancel()
	ip := net.ParseIP(*rbl)
	c := make(chan interface{}, len(rbls)+1)
	check_rbl(ip, true, c)
	for {
		select {
		case <-gg.Done():
			return
		case r := <-c:
			switch t := r.(type) {
			case *rbl_result:
				j.Infof("rbls: %v : %v %v\n", ip.String(), t.Rbl, t.Found)
			default:
				return
			}
		}
	}
}

type Stime time.Time

func (o *Stime) Scan(v interface{}) error {
	switch t := v.(type) {
	case int64:
		*o = Stime(time.Unix(t, 0))
	default:
		return fmt.Errorf("unsupported type: %T: %v", t, t)
	}
	return nil
}
