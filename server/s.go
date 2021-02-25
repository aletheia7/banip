// Copyright 2018 aletheia7. All rights reserved. Use of this source code is
// governed by a BSD-2-Clause license that can be found in the LICENSE file.

package server

import (
	"banip/filter"
	"banip/list"
	br "banip/rbl"
	"bufio"
	"bytes"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/aletheia7/gogroup"
	"github.com/aletheia7/mbus"
	"github.com/aletheia7/sd"
	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
	j         = sd.New()
	toml_dir  = flag.String("toml", "", "toml directory, default: <user home>/toml")
	sqlite    = flag.String("sqlite", "banip.sqlite", "if not exist: will be made")
	nolog     = flag.Bool("nolog", false, "nolog")
	queue_id  = flag.Uint("queue", 77, "queue id 16 bit, needs to match nfttables rule queue num")
	ban_dur   = flag.Duration("bdur", time.Duration(time.Hour*24*7), "ban duration, default: 7 days")
	stats_dur = flag.Duration("stats", time.Duration(time.Hour), "stats dur, default: hourly")
)

const tsfmt = `2006-01-02 15:04:05-07:00`

type new_con struct {
	ip net.IP
	ts time.Time
}

type Server struct {
	gg   *gogroup.Group
	home string
	// 4 byte string key
	wb    *list.WB
	db    *sql.DB
	rbl   *br.Search
	rbls  []string
	stats stat
	// cnew              chan *new_con
}

type stat struct {
	con, banned, wl, bl, accept int
}

func New(gg *gogroup.Group, home string, rbls []string) *Server {
	o := &Server{
		gg:   gg,
		home: home,
		wb:   list.New(),
		db:   get_database(gg, home),
		rbl:  br.New(gg, rbls),
		rbls: rbls,
	}
	if o.db == nil {
		return o
	}
	rows, err := o.db.QueryContext(o.gg, "select ip, ban, ts from ip")
	if err != nil {
		j.Err(err)
		return o
	}
	var (
		now    = time.Now()
		exp_ct = 0
		ip     string
		ban    int
		ts     time.Time
	)
	for rows.Next() {
		if err = rows.Scan(&ip, &ban, (*Stime)(&ts)); err != nil {
			j.Err(err)
			return o
		}
		// only expire blacklist
		if ban == 1 && ts.Add(*ban_dur).Before(now) {
			exp_ct++
			continue
		}
		switch {
		case ban == 0:
			o.wb.W.Add(ip)
		case !o.wb.W.Lookup(net.ParseIP(ip)):
			o.wb.B.Add(ip, &ts)
		}
	}
	if err = rows.Err(); err != nil {
		j.Err(err)
	}
	j.Info("ban duration:", *ban_dur)
	j.Info("whitelist:", o.wb.W.Len())
	j.Info("blacklist:", o.wb.B.Len())
	j.Info("expired:", exp_ct)
	return o
}

func (o *Server) WB() *list.WB {
	return o.wb
}

var run_once sync.Once

func (o *Server) Run(since string, nf_mode bool) {
	run_once.Do(func() {
		if nf_mode {
			o.run_nf()
		} else {
			o.run(since)
		}
	})
}

func (o *Server) run_nf() {
	key := o.gg.Register()
	defer o.gg.Unregister(key)
	j.Info("mode: nf")
	go o.expire()
	var nf *nfqueue.Nfqueue
	var err error
	if nf, err = nfqueue.Open(&nfqueue.Config{
		NfQueue:      uint16(*queue_id),
		Copymode:     nfqueue.NfQnlCopyPacket,
		MaxQueueLen:  0xff,
		MaxPacketLen: 0xffff,
		ReadTimeout:  time.Second * 3,
	}); err != nil {
		j.Err("could not open nflog socket:", err)
		return
	}
	defer func() {
		if err := nf.Close(); err != nil {
			j.Err("nf.close:", err)
		}
	}()
	j.Warning("Register fn")
	var ip4 layers.IPv4
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4)
	parser.SetDecodingLayerContainer(gopacket.DecodingLayerSparse(nil))
	parser.AddDecodingLayer(&ip4)
	parser.IgnoreUnsupported = true
	decoded := []gopacket.LayerType{}
	if err = nf.Register(o.gg, func(a nfqueue.Attribute) int {
		if err = parser.DecodeLayers(*a.Payload, &decoded); err != nil {
			j.Err("DecodeLayers err", err)
			return 0
		}
		o.stats.con++
		select {
		case <-o.gg.Done():
			if err = nf.SetVerdict(*a.PacketID, nfqueue.NfAccept); err != nil {
				j.Warning(err)
			}
			return 1
		default:
			switch {
			case o.wb.W.Lookup(ip4.SrcIP):
				if err = nf.SetVerdict(*a.PacketID, nfqueue.NfAccept); err != nil {
					j.Warning(err)
				}
				o.stats.wl++
			case o.wb.B.Lookup(ip4.SrcIP):
				if err = nf.SetVerdict(*a.PacketID, nfqueue.NfDrop); err != nil {
					j.Warning(err)
				}
				ip := ip4.SrcIP.To4().String()
				id, updated := o.Bl_update_ts(ip)
				if updated {
					if !*nolog {
						j.Infof("blacklist update: nf %v %v", id, ip)
					}
				}
				o.stats.bl++
			default:
				if aa := o.rbl.Lookup(ip4.SrcIP, true); 0 < len(aa) {
					if err = nf.SetVerdict(*a.PacketID, nfqueue.NfDrop); err != nil {
						j.Warning(err)
					}
					o.stats.banned++
					ip := ip4.SrcIP.To4().String()
					id := o.Bl(ip, `nf`, aa[0], nil)
					if !*nolog {
						j.Infof("blacklist: nf %v %v %v", id, ip, aa[0])
					}
				} else {
					if err = nf.SetVerdict(*a.PacketID, nfqueue.NfAccept); err != nil {
						j.Warning(err)
					}
					o.stats.accept++
				}
			}
		}
		if o.gg.Err() != nil {
			return 1
		}
		return 0
	}); err != nil {
		j.Err(err)
		return
	}
	j.Warning("After register")
	<-o.gg.Done()
}

func (o *Server) expire() {
	key := o.gg.Register()
	defer o.gg.Unregister(key)
	for {
		select {
		case <-o.gg.Done():
			return
		case <-time.After(*stats_dur):
			j.Infof("new cons: %v, new bans: %v, wl: %v, bl: %v, accept: %v\n", o.stats.con, o.stats.banned, o.stats.wl, o.stats.bl, o.stats.accept)
			o.stats = stat{}
		case <-time.After(time.Hour * 24):
			j.Info("begin expire:", o.wb.B.Len())
			j.Info("end expire:", o.wb.B.Expire(*ban_dur))
		}
	}
}

func (o *Server) run(since string) {
	key := o.gg.Register()
	defer o.gg.Unregister(key)
	bus := mbus.New_bus(o.gg)
	c := make(chan *mbus.Msg, 256)
	bus.Subscribe(c, filter.T_bl)
	defer bus.Unsubscribe(c, filter.T_bl)
	o.run_filter(bus, since)
	for {
		select {
		case <-o.gg.Done():
		case in := <-c:
			switch in.Topic {
			case filter.T_bl:
				if a, ok := in.Data.(*filter.Action); ok {
					ip := net.ParseIP(a.Ip).To4()
					if ip != nil {
						j.Warning("invalid ip:", a.Ip)
						return
					}
					switch {
					case o.wb.W.Lookup(ip) || o.wb.B.Lookup(ip):
					default:
						var rbl_found interface{}
						if a.Check_rbl {
							if a := o.rbl.Lookup(ip, true); 0 < len(a) {
								rbl_found = a[0]
							}
						}
						id := o.Bl(a.Ip, a.Toml, rbl_found, a.Msg)
						if !*nolog {
							j.Infof("blacklist: %v %v %v %v", a.Toml, id, a.Ip, rbl_found)
						}
					}
				}
			}
		}
	}
}

func (o *Server) Wl(ip string) {
	i, err := list.Valid_ip_cidr(ip)
	if err != nil {
		j.Err(err)
		return
	}
	var s string
	var present bool
	switch t := i.(type) {
	case *net.IP:
		s = t.String()
		present = o.wb.W.Lookup(*t)
	case *net.IPNet:
		s = t.String()
	default:
		j.Err("unknown value:", i)
		return
	}
	if !present {
		o.wb.W.Add(s)
		if _, err := o.db.ExecContext(o.gg, "replace into ip(ip, ban, ts, toml) values(:ip, 0, :ts, null)", sql.Named("ip", s), sql.Named("ts", time.Now().Format(tsfmt))); err != nil {
			j.Err(err)
		}
	}
}

func (o *Server) Q(ip string) {
	var (
		oid            int64
		ban            bool
		ts             time.Time
		toml, log, rbl sql.NullString
	)
	i, err := list.Valid_ip_cidr(ip)
	if err != nil {
		j.Err(err)
		return
	}
	var s string
	switch t := i.(type) {
	case *net.IP:
		s = t.String()
	case *net.IPNet:
		s = t.String()
	default:
		j.Err("unknown value:", i)
		return
	}
	err = o.db.QueryRowContext(o.gg, "select oid, ban, ts, toml, log, rbl from ip where ip = :ip order by ban limit 1", sql.Named("ip", s)).Scan(&oid, &ban, (*Stime)(&ts), &toml, &log, &rbl)
	switch err {
	case sql.ErrNoRows:
		return
	case nil:
	default:
		j.Err(err)
		return
	}
	j.Info("oid:", oid)
	j.Info("ban:", ban)
	j.Info("ts:", ts.Format("2006-01-02 15:04:05"))
	if toml.Valid {
		j.Info("toml:", toml.String)
	}
	if log.Valid {
		j.Info("log:", log.String)
	}
	if rbl.Valid {
		j.Info("rbl:", rbl.String)
	}
}

func (o *Server) Bl(ip, toml string, rbl, log interface{}) (last_insert_id int64) {
	i, err := list.Valid_ip_cidr(ip)
	if err != nil {
		j.Err(err)
		return
	}
	var s string
	var present bool
	switch t := i.(type) {
	case *net.IP:
		s = t.String()
		present = o.wb.B.Lookup(*t)
	case *net.IPNet:
		j.Err("cannot blacklist network:", ip)
		return
	default:
		j.Err("unknown value:", i)
		return
	}
	if present {
		return -1
	}
	ts := time.Now()
	o.wb.B.Add(ip, &ts)
	res, err := o.db.ExecContext(o.gg, "insert or ignore into ip(ip, ban, ts, toml, rbl, log) values(:ip, 1, :ts, :toml, :rbl, :log)",
		sql.Named("ip", s),
		sql.Named("ts", ts.Format(tsfmt)),
		sql.Named("toml", toml),
		sql.Named("rbl", rbl),
		sql.Named("log", log),
	)
	if err != nil {
		j.Err(err)
		return
	}
	last_insert_id, err = res.LastInsertId()
	if err != nil {
		j.Warning(err)
	}
	return
}

func (o *Server) Bl_update_ts(ip string) (last_insert_id int64, updated bool) {
	i, err := list.Valid_ip_cidr(ip)
	if err != nil {
		j.Err(err)
		return
	}
	var s string
	var present bool
	var old_ts *time.Time
	switch t := i.(type) {
	case *net.IP:
		s = t.String()
		old_ts, present = o.wb.B.Lookup_all(*t)
	case *net.IPNet:
		j.Err("cannot blacklist network:", ip)
		return
	default:
		j.Err("unknown value:", i)
		return
	}
	ts := time.Now()
	// Only update sqlite every 24h
	if !present {
		j.Err("ip should be present:", s)
		return
	}
	if old_ts.Add(time.Hour * 24).After(ts) {
		return
	}
	o.wb.B.Add(ip, &ts)
	res, err := o.db.ExecContext(o.gg, "update ip set ts = :ts where ip = :ip",
		sql.Named("ts", ts.Format(tsfmt)),
		sql.Named("ip", s),
	)
	if err != nil {
		j.Err(err)
		return
	}
	last_insert_id, err = res.LastInsertId()
	if err != nil {
		j.Warning(err)
	}
	updated = true
	return
}

func (o *Server) Rm(ip string) {
	i, err := list.Valid_ip_cidr(ip)
	if err != nil {
		j.Err(err)
		return
	}
	var s string
	switch t := i.(type) {
	case *net.IP:
		s = t.String()
	case *net.IPNet:
		s = t.String()
	default:
		j.Err("unknown value:", i)
		return
	}
	o.wb.W.Remove(s)
	o.wb.B.Remove(s)
	if _, err := o.db.ExecContext(o.gg, "delete from ip where ip = :ip", sql.Named("ip", s)); err != nil {
		j.Err(err)
	}
}

func (o *Server) run_filter(bus *mbus.Bus, since string) {
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
		f, err := filter.New(o.gg, bus, p, o.wb, o.rbls)
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
	Journal(o.gg, bus, false, a, since)
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
    ip text not null unique
  , ban int not null check(ban in (0, 1))
  , ts datetime not null
  , toml text
  , rbl text
  , log text
);
-- vim: ts=2 expandtab`

type m struct {
	Tag     string      `json:"SYSLOG_IDENTIFIER"`
	Message interface{} `json:"MESSAGE"`
}

func Journal(gg *gogroup.Group, bus *mbus.Bus, test bool, tag []string, since string) {
	tag_args := make([]string, 0, (len(tag)*2)+6)
	if 0 < len(since) {
		j.Info("since:", since)
		tag_args = append(tag_args, "--since", since)
	}
	if test {
		tag_args = append(tag_args, "--output", "json")
	} else {
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
			var s string
			switch t := m.Message.(type) {
			case string:
				s = t
			case []byte:
				s = string(t)
			}
			if test {
				bus.Pub(filter.T_test, s)
			} else {
				bus.Pub(m.Tag, s)
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
	case []byte:
		ts, err := time.Parse(string(t), tsfmt)
		if err != nil {
			return err
		}
		*o = Stime(ts)
	case time.Time:
		*o = Stime(t)
	default:
		return fmt.Errorf("unsupported type: %T: %v", t, t)
	}
	return nil
}
