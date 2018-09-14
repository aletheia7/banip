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
	"github.com/aletheia7/sd"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
)

var (
	j = sd.New()
	// j        = sd.New(sd.Set_default_writer_stdout(), sd.Set_default_disable_journal(true))
	testdata = flag.String("testdata", "", "path to toml, use testdata")
	test     = flag.String("test", "", "path to toml, use journalctl")
	test_nft = flag.Bool("testnft", false, "add gobanip")
	pmatched = flag.Bool("pmatched", false, "print matched w/ -test")
	pmissed  = flag.Bool("pmissed", false, "print missed w/ -test")
	wl       = flag.String("wl", "", "whitelist IP")
	rml      = flag.String("rml", "", "remove from list")
	rbl      = flag.String("rbl", "", "query rbls")
	device   = flag.String("device", "br0", "netdev device")
	sqlite   = flag.String("sqlite", "banip.sqlite", "will be made when not exists")
	gg       = gogroup.New(gogroup.Add_signals(gogroup.Unix))
	ipv4b    = []byte{36, 105, 112, 118, 52} // $ipv4
)

func main() {
	flag.Parse()
	switch {
	case 0 < len(*rbl):
		go do_rbl()
	case *test_nft:
		t, err := nft.New_table(`netdev`, `filter`, `gobanip`, *device)
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
	case 0 < len(*test):
		j.Info("test:", *test)
		conf, err := filter.New(*test)
		if err != nil {
			return
		}
		src, err := journal(conf)
		if err != nil {
			return
		}
		go do_test(conf, src)
	case 0 < len(*testdata):
		j.Info("testdata:", *testdata)
		conf, err := filter.New(*testdata)
		if err != nil {
			return
		}
		src := make(chan []byte, 1)
		go func() {
			defer close(src)
			for _, b := range conf.Testdata {
				select {
				case <-gg.Done():
					return
				default:
					src <- b
				}
			}
		}()
		go do_test(conf, src)
	default:
		go server()
	}
	defer gg.Wait()
	<-gg.Done()
}

func server() {
	key := gg.Register()
	defer gg.Unregister(key)
	db := get_database()
	if db == nil {
		return
	}
	// 4 byte string key
	list := map[string]bool{}
	rows, err := db.QueryContext(gg, "select ip, ban from ip")
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
			list[net.ParseIP(ip).To4().String()] = false
		} else {
			bl = append(bl, ip)
			list[net.ParseIP(ip).To4().String()] = true
		}
	}
	if err = rows.Err(); err != nil {
		j.Err(err)
		return
	}
	j.Info("whitelist:", wl_ct)
	j.Info("blacklist:", len(bl))
	bset, e := nft.New_table(`netdev`, `filter`, `gobanip`, *device)
	if e != nil {
		j.Err(e)
		return
	}
	if 0 < len(bl) {
		bset.Add_set(bl...)
	}
}

// create sql db

// tasks
// load tomls
// load/unload nftables
// get -t(s) for journalctl and start journalctl
func get_database() *sql.DB {
	cwd, err := os.Getwd()
	if err != nil {
		j.Err(err)
		gg.Cancel()
		return nil
	}
	db, err := sql.Open("sqlite3", "file://"+cwd+"/"+*sqlite+"?"+strings.Join([]string{"_journal=wal", "_fk=1", "_timeout=30"}, `&`))
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

func journal(conf *filter.Filter) (chan []byte, error) {
	src := make(chan []byte, 256)
	tag := make([]string, 0, len(conf.Tag)*2)
	for _, t := range conf.Tag {
		tag = append(tag, "-t", t)
	}
	cmd := exec.CommandContext(gg, "journalctl", append([]string{""}, tag...)...)
	var e bytes.Buffer
	rp, wp := io.Pipe()
	cmd.Stdout = wp
	cmd.Stderr = &e
	if err := cmd.Start(); err != nil {
		j.Err(err)
		return nil, err
	}
	go func() {
		defer rp.Close()
		defer close(src)
		scanner := bufio.NewScanner(rp)
		for scanner.Scan() {
			var m map[string]interface{}
			if err := json.NewDecoder(bytes.NewReader(scanner.Bytes())).Decode(&m); err != nil {
				j.Err(err)
				continue
			}
			src <- []byte(m["MESSAGE"].(string))
		}
		if err := scanner.Err(); err != nil {
			j.Err(err)
		}
	}()
	go func() {
		defer wp.Close()
		if err := cmd.Wait(); err != nil {
			j.Err(err, e.String())
		}
	}()
	return src, nil
}

func do_rbl() {
	defer gg.Cancel()
	ip := net.ParseIP(*rbl).To4()
	for i, j := 0, len(ip)-1; i < j; i, j = i+1, j-1 {
		ip[i], ip[j] = ip[j], ip[i]
	}
	for _, h := range []string{
		ip.String() + ".sbl-xbl.spamhaus.org",
		ip.String() + ".bl.spamcop.net",
		ip.String() + ".dnsbl.sorbs.net",
		ip.String() + ".dnsbl-1.uceprotect.net",
		ip.String() + ".dnsbl-2.uceprotect.net",
		ip.String() + ".dnsbl-3.uceprotect.net",
	} {
		a, err := net.LookupHost(h)
		if err != nil {
			j.Info(h, "not found")
			continue
		}
		for _, s := range a {
			j.Info(h, s)
		}
	}
}

func do_test(conf *filter.Filter, src chan []byte) {
	defer gg.Cancel()
	matched := 0
	total := 0
	for t := range src {
		select {
		case <-gg.Done():
		default:
			total++
			for _, re := range conf.Re {
				b := re.Expand(nil, ipv4b, t, re.FindSubmatchIndex(t))
				if b == nil {
					if *pmissed {
						j.Infof("missed: %s\n", t)
					}
				} else {
					matched++
					if *pmatched {
						j.Infof("matched: %s\n", b)
					}
				}
			}
		}
	}
	j.Infof("matched: %v, missed: %v, total: %v\n", matched, total-matched, total)
}
