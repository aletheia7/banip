// Copyright 2018 aletheia7. All rights reserved. Use of this source code is
// governed by a BSD-2-Clause license that can be found in the LICENSE file.

package server

import (
	"banip/filter"
	"banip/list"
	"banip/nft"
	br "banip/rbl"
	"bufio"
	"bytes"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/aletheia7/gogroup"
	"github.com/aletheia7/mbus"
	"github.com/aletheia7/nfqueue"
	"github.com/aletheia7/sd"
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
const tsfmthigh = `2006-01-02 15:04:05.999-07:00`

type new_con struct {
	ip net.IP
	ts time.Time
}

type Server struct {
	gg   *gogroup.Group
	home string
	// 4 byte string key
	list                                *list.WB
	db                                  *sql.DB
	rbl                                 *br.Search
	rbls                                []string
	con_ct, banned_ct, bl_ct, accept_ct int
	// cnew              chan *new_con
}

func New(gg *gogroup.Group, home string, rbls []string) *Server {
	o := &Server{
		gg:   gg,
		home: home,
		list: list.New(),
		db:   get_database(gg, home),
		rbl:  br.New(gg, rbls),
		rbls: rbls,
		// cnew: make(chan *new_con, 512),
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
		if ban == 0 {
			o.list.W.Add(ip)
		} else {
			o.list.B.Add(ip, &ts)
		}
	}
	if err = rows.Err(); err != nil {
		j.Err(err)
	}
	j.Info("whitelist:", o.list.W.Len())
	j.Info("blacklist:", o.list.B.Len())
	j.Info("expired:", exp_ct)
	return o
}

func (o *Server) WB() *list.WB {
	return o.list
}

var run_once sync.Once

func (o *Server) Run(device, since string, nf_mode bool) {
	run_once.Do(func() {
		if nf_mode {
			o.run_nf()
		} else {
			o.run(device, since)
		}
	})
}

type Queue struct {
	n *nfqueue.Queue
	s *Server
}

func New_queue(id uint16, s *Server) *Queue {
	q := &Queue{}
	q.n = nfqueue.NewQueue(id, q, &nfqueue.QueueConfig{MaxPackets: 5000, BufferSize: 16 * 1024 * 1024})
	q.s = s
	return q
}

func (o *Queue) Handle(p *nfqueue.Packet) {
	var ip4 layers.IPv4
	var tcp layers.TCP
	var udp layers.UDP
	var payload gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &tcp, &udp, &payload)
	parser.IgnorePanic = true
	parser.IgnoreUnsupported = true
	decoded := make([]gopacket.LayerType, 0, 10)
	err := parser.DecodeLayers(p.Buffer, &decoded)
	if err != nil {
		j.Warning("DecodeLayers err", err)
		return
	}
	o.s.con_ct++
	// o.s.cnew <- &new_con{ip: ip4.SrcIP, ts: time.Now()}
	// j.Errf("debug rx %v:%d -> %v:%d\n", ip4.SrcIP, tcp.SrcPort, ip4.DstIP, tcp.DstPort)
	select {
	case <-o.s.gg.Done():
		if err = p.Accept(); err != nil {
			j.Warning(err)
		}
	default:
		switch {
		case o.s.list.W.Lookup(ip4.SrcIP):
			if err = p.Accept(); err != nil {
				j.Warning(err)
			}
		case o.s.list.B.Lookup(ip4.SrcIP):
			o.s.bl_ct++
			if err = p.Drop(); err != nil {
				j.Warning(err)
			}
		default:
			if a := o.s.rbl.Lookup(ip4.SrcIP, true); 0 < len(a) {
				now := time.Now()
				ip := ip4.SrcIP.To4().String()
				o.s.list.B.Add(ip, &now)
				res, err := o.s.db.ExecContext(o.s.gg, "insert or ignore into ip(ip, ban, ts, toml, rbl) values(:ip, 1, :ts, :toml, :rbl)", sql.Named("ip", ip), sql.Named("ts", now.Format(tsfmt)), sql.Named("toml", `nf`), sql.Named("rbl", a[0]))
				if err != nil {
					j.Warning(err)
				}
				id, err := res.LastInsertId()
				if err != nil {
					j.Warning(err)
				}
				o.s.banned_ct++
				if !*nolog {
					j.Infof("blacklist: nf %v %v %v", id, ip4.SrcIP.To4().String(), a[0])
				}
				if err = p.Drop(); err != nil {
					j.Warning(err)
				}
			} else {
				o.s.accept_ct++
				if err = p.Accept(); err != nil {
					j.Warning(err)
				}
			}
		}
	}
}

func (o *Server) run_nf() {
	key := o.gg.Register()
	defer o.gg.Unregister(key)
	q := New_queue(uint16(*queue_id), o)
	go q.n.Start()
	go o.expire()
	// go o.new_con()
	j.Info("started")
	<-o.gg.Done()
	q.n.Stop()
	defer j.Info("ended")
}

func (o *Server) new_con() {
	key := o.gg.Register()
	defer o.gg.Unregister(key)
	for {
		select {
		case <-o.gg.Done():
			return
		case <-time.After(*stats_dur):
			j.Infof("new cons: %v, new bans: %v\n", o.con_ct, o.banned_ct)
			o.con_ct = 0
			o.banned_ct = 0
		case <-time.After(time.Hour * 24):
			j.Info("begin expire:", o.list.B.Len())
			j.Info("end expire:", o.list.B.Expire(*ban_dur))
		}
	}
}

func (o *Server) expire() {
	key := o.gg.Register()
	defer o.gg.Unregister(key)
	// cn_cache := make([]*new_con, 0, 1000)
	// ins, err := o.db.PrepareContext(o.gg, "insert into con values(:ip, :ts)")
	// if err != nil {
	// 	j.Err(err)
	// 	return
	// }
	// defer ins.Close()
	for {
		select {
		case <-o.gg.Done():
			// tgg := gogroup.New(gogroup.With_timeout(gogroup.New(), time.Second*3))
			// o.write_db(tgg, cn_cache, ins)
			return
		// case <-o.cnew:
		// cn_cache = append(cn_cache, n)
		// case <-time.After(time.Minute):
		// 	if err = o.write_db(o.gg, cn_cache, ins); err != nil {
		// 		return
		// 	}
		case <-time.After(*stats_dur):
			j.Infof("new cons: %v, new bans: %v, bl: %v, accept: %v\n", o.con_ct, o.banned_ct, o.bl_ct, o.accept_ct)
			o.con_ct = 0
			o.banned_ct = 0
		case <-time.After(time.Hour * 24):
			j.Info("begin expire:", o.list.B.Len())
			j.Info("end expire:", o.list.B.Expire(*ban_dur))
		}
	}
}

// func (o *Server) write_db(gg *gogroup.Group, cn_cache []*new_con, ins *sql.Stmt) error {
// 	tx, err := o.db.BeginTx(gg, nil)
// 	if err != nil {
// 		j.Err(err)
// 		return err
// 	}
// 	for _, cn := range cn_cache {
// 		if _, err = tx.Stmt(ins).ExecContext(gg, sql.Named("ip", cn.ip.To4().String()), sql.Named("ts", cn.ts.Format(tsfmthigh))); err != nil {
// 			j.Err(err)
// 			return err
// 		}
// 	}
// 	if err = tx.Commit(); err != nil {
// 		j.Err(err)
// 		return err
// 	}
// 	cn_cache = cn_cache[:0]
// 	return nil
// }

func (o *Server) run(device, since string) {
	key := o.gg.Register()
	defer o.gg.Unregister(key)
	bset, e := nft.New_table(`inet`, `filter`, `banip`, device)
	if e != nil {
		j.Err(e)
		return
	}
	bset.Add_set(o.list.B.All()...)
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
					case o.list.W.Lookup(ip) || o.list.B.Lookup(ip):
					default:
						ts := time.Now()
						if err := o.list.B.Add(a.Ip, &ts); err != nil {
							j.Warning(err)
						}
						if err := bset.Add_set(a.Ip); err != nil {
							j.Warning(err)
						}
						var rbl_found interface{}
						if a.Check_rbl {
							if a := o.rbl.Lookup(ip, true); 0 < len(a) {
								rbl_found = a[0]
							}
						}
						res, err := o.db.ExecContext(o.gg, "insert or ignore into ip(ip, ban, ts, toml, rbl, log) values(:ip, 1, :ts, :toml, :rbl, :log)", sql.Named("ip", a.Ip), sql.Named("ts", ts.Format(tsfmt)), sql.Named("toml", a.Toml), sql.Named("rbl", rbl_found), sql.Named("log", a.Msg))
						if err != nil {
							j.Err(err)
							return
						}
						id, err := res.LastInsertId()
						if err != nil {
							j.Err(err)
						}
						if !*nolog {
							j.Infof("blacklist: %v %v %v %v", a.Toml, id, a.Ip, rbl_found)
						}
					}
				}
			}
		}
	}
}

func (o *Server) Wl(ip net.IP) {
	if _, err := o.db.ExecContext(o.gg, "replace into ip(ip, ban, ts, toml) values(:ip, 0, :ts, null)", sql.Named("ip", ip.To4().String()), sql.Named("ts", time.Now().Format(tsfmt))); err != nil {
		j.Err(err)
	}
}

func (o *Server) Q(ip net.IP) {
	var (
		oid            int64
		ban            bool
		ts             time.Time
		toml, log, rbl sql.NullString
	)
	err := o.db.QueryRowContext(o.gg, "select oid, ban, ts, toml, log, rbl from ip where ip = :ip", sql.Named("ip", ip.To4().String())).Scan(&oid, &ban, (*Stime)(&ts), &toml, &log, &rbl)
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

func (o *Server) Bl(ip net.IP) {
	if _, err := o.db.ExecContext(o.gg, "insert or ignore into ip(ip, ban, ts, toml) values(:ip, 1, :ts, 'blip')", sql.Named("ip", ip.To4().String()), sql.Named("ts", time.Now().Format(tsfmt))); err != nil {
		j.Err(err)
	}
}

func (o *Server) Rm(ip net.IP) {
	if _, err := o.db.ExecContext(o.gg, "delete from ip where ip = :ip", sql.Named("ip", ip.To4().String())); err != nil {
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
		f, err := filter.New(o.gg, bus, p, o.list, o.rbls)
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
