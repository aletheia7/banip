// Copyright 2018 aletheia7. All rights reserved. Use of this source code is
// governed by a BSD-2-Clause license that can be found in the LICENSE file.

package server

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
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	j        = sd.New()
	toml_dir = flag.String("toml", "", "toml directory, default: <user home>/toml")
	sqlite   = flag.String("sqlite", "banip.sqlite", "if not exist: will be made")
)

const tsfmt = `2006-01-02 15:04:05-07:00`

type Server struct {
	gg     *gogroup.Group
	home   string
	device string
	// 4 byte string key
	list    map[string]bool
	mu_list sync.RWMutex
	db      *sql.DB
}

func New(gg *gogroup.Group, home, device string) *Server {
	o := &Server{
		gg:     gg,
		home:   home,
		device: device,
		list:   map[string]bool{},
		db:     get_database(gg, home),
	}
	if o.db == nil {
		return o
	}
	rows, err := o.db.QueryContext(o.gg, "select ip, ban from ip")
	if err != nil {
		j.Err(err)
		return o
	}
	var ip string
	var ban int
	wl_ct := 0
	bl_ct := 0
	for rows.Next() {
		if err = rows.Scan(&ip, &ban); err != nil {
			j.Err(err)
			return o
		}
		if ban == 0 {
			wl_ct++
			o.list[string(net.ParseIP(ip).To4())] = false
		} else {
			bl_ct++
			o.list[string(net.ParseIP(ip).To4())] = true
		}
	}
	if err = rows.Err(); err != nil {
		j.Err(err)
	}
	j.Info("whitelist:", wl_ct)
	j.Info("blacklist:", bl_ct)
	return o
}

var run_once sync.Once

func (o *Server) Run() {
	run_once.Do(func() {
		o.run()
	})
}

func (o *Server) run() {
	key := o.gg.Register()
	defer o.gg.Unregister(key)
	o.mu_list.RLock()
	bl := make([]string, 0, len(o.list))
	for ip_bin := range o.list {
		bl = append(bl, net.IP(ip_bin).String())
	}
	o.mu_list.RUnlock()
	bset, e := nft.New_table(`inet`, `filter`, `banip`, o.device)
	if e != nil {
		j.Err(e)
		return
	}
	if 0 < len(bl) {
		bset.Add_set(bl...)
	}
	bl = nil
	bus := mbus.New_bus(o.gg)
	c := make(chan *mbus.Msg, 256)
	bus.Subscribe(c, filter.T_bl)
	defer bus.Unsubscribe(c, filter.T_bl)
	// list_mu must be used after run_filter
	o.run_filter(bus)
	for {
		select {
		case <-o.gg.Done():
			return
		case in := <-c:
			switch in.Topic {
			case filter.T_bl:
				if a, ok := in.Data.(*filter.Action); ok {
					ip := net.ParseIP(a.Ip).To4()
					ip_bin := string(ip)
					_, found := o.In_list(ip)
					if !found {
						o.mu_list.Lock()
						o.list[ip_bin] = true
						o.mu_list.Unlock()
						if err := bset.Add_set(a.Ip); err != nil {
							j.Err(err)
							return
						}
						var rbl_found interface{} = nil
						if a.Check_rbl {
							c := make(chan interface{}, 2)
							filter.Check_rbl(o.gg, ip, false, c)
							select {
							case <-o.gg.Done():
								return
							case r := <-c:
								switch t := r.(type) {
								case *filter.Rbl_result:
									if t.Found {
										rbl_found = t.Rbl
									}
								default:
									return
								}
							}
						}
						res, err := o.db.ExecContext(o.gg, "insert or ignore into ip(ip, ban, ts, toml, rbl, log) values(:ip, 1, :ts, :toml, :rbl, :log)", sql.Named("ip", a.Ip), sql.Named("ts", time.Now().Format(tsfmt)), sql.Named("toml", a.Toml), sql.Named("rbl", rbl_found), sql.Named("log", a.Msg))
						if err != nil {
							j.Err(err)
							return
						}
						id, err := res.LastInsertId()
						if err != nil {
							j.Err(err)
						}
						j.Infof("blacklist: %v %v %v %v", a.Toml, id, a.Ip, rbl_found)
					}
				}
			}
		}
	}
}

// value: whitelist: false, blacklist: true
func (o *Server) In_list(ip net.IP) (value, found bool) {
	o.mu_list.RLock()
	defer o.mu_list.RUnlock()
	value, found = o.list[string(ip.To4())]
	return
}

func (o *Server) run_filter(bus *mbus.Bus) {
	td := filepath.Join(o.home, "toml", "*.toml")
	if 0 < len(*toml_dir) {
		td = filepath.Join(*toml_dir, "*.toml")
	}
	j.Info("toml:", td)
	toml, err := filepath.Glob(td)
	if err != nil {
		j.Err(err)
		return
	}
	enabled := false
	tag := map[string]bool{}
	for _, p := range toml {
		f, err := filter.New(o.gg, bus, p, o)
		if err != nil {
			j.Err(err)
			return
		}
		if !f.Enabled {
			f.Stop()
			continue
		}
		enabled = true
		for _, t := range f.Tag {
			tag[t] = true
		}
	}
	a := make([]string, 0, len(tag))
	for s := range tag {
		a = append(a, s)
	}
	if !enabled {
		j.Warning("No filters are enabled")
		j.Warning("No action will occur")
		j.Warning(`Filters with "enabled = true" must be available`)
		j.Warning("Execute: mkdir <directory>")
		j.Warning("Copy & edit your favorite *.toml to your <directroy>")
		j.Warning("Execute: systemctl restart banip")
		j.Warning("Typical of a new installation 😊")
	}
	Journal(o.gg, bus, false, a)
}

func get_database(gg *gogroup.Group, home string) *sql.DB {
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

type m struct {
	Tag     string `json:"SYSLOG_IDENTIFIER"`
	Message string `json:"MESSAGE"`
}

type Pubor interface {
	Pub(topic string, data interface{})
}

func Journal(gg *gogroup.Group, pub Pubor, test bool, tag []string) {
	var tag_args []string
	if test {
		tag_args = make([]string, 0, (len(tag)*2)+2)
		tag_args = append(tag_args, "--output", "json")
	} else {
		tag_args = make([]string, 0, (len(tag)*2)+4)
		tag_args = append(tag_args, "-n", "all", "-f", "--output", "json")
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
				pub.Pub(filter.T_test, nil)
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
				pub.Pub(filter.T_test, m.Message)
			} else {
				pub.Pub(m.Tag, m.Message)
			}
		}
		if err := scanner.Err(); err != nil {
			j.Err(err)
		}
	}()
	go func() {
		defer wp.Close()
		cmd.Wait()
	}()
	return
}

func Load_fail2ban(gg *gogroup.Group, f2bdb, home string) {
	defer gg.Cancel()
	if _, err := os.Stat(f2bdb); err != nil {
		j.Err(err)
		return
	}
	fdb, err := sql.Open("sqlite3", "file://"+f2bdb+"?"+strings.Join([]string{"_journal=wal", "_fk=1", "_timeout=30000"}, `&`))
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
	db := get_database(gg, home)
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
