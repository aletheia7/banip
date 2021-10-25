package main

import (
	"banip/rlog"
	"database/sql"
	"flag"
	"io/ioutil"
	"net/url"
	"os"
	"path"

	"github.com/aletheia7/gogroup/v2"
	"github.com/aletheia7/sd/v6"
	_ "github.com/mattn/go-sqlite3"
)

var (
	j          = sd.New(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
	gg         = gogroup.New(gogroup.Add_signals(gogroup.Unix))
	max_size   = 100_000_000
	make_table = flag.Bool(`make-table`, false, `issue create table, etc.`)
	test_db    = flag.String(`db`, `banip-rlog.sqlite`, ``)
)

func main() {
	flag.Parse()
	go load()
	defer gg.Wait()
	<-gg.Done()
}

func load() {
	key := gg.Register()
	defer gg.Unregister(key)
	fp, err := os.Open(`../../testdata/t.json`)
	if err != nil {
		j.Err(err)
		return
	}
	defer fp.Close()
	wd, _ := os.Getwd()
	c := rlog.New_listener(gg, fp)
	db, err := sql.Open(`sqlite3`, (&url.URL{
		Scheme: `file`,
		Path:   path.Join(wd, *test_db),
		RawQuery: url.Values{
			`_journal`: []string{`wal`},
			`_cache`:   []string{`private`},
			`_fk`:      []string{`1`},
			`_timeout`: []string{`30000`},
		}.Encode(),
	}).String())
	if err != nil {
		j.Err(err)
		return
	}
	defer db.Close()
	if *make_table {
		b, err := ioutil.ReadFile(`../../testdata/make.sql`)
		if err != nil {
			j.Err(err)
			return
		}
		if _, err := db.ExecContext(gg, string(b)); err != nil {
			j.Err(err)
			return
		}
	}
	tx, err := db.BeginTx(gg, nil)
	if err != nil {
		j.Err(err)
		return
	}
	defer tx.Commit()
	ins, err := tx.PrepareContext(gg, `
insert or replace into rlog(
	score, max_score, mfrom, ip, uid, t, is_spam, action, forced_action, mid, user, smtp_from, smtp_rcpts, subject, asn, ipnet, country, ssp, len, time_real, time_virtual, dns_req, digest, mime_rcpts, filename, qid, settings_id, cursor
	)
values(
	:score, :max_score, :mfrom, :ip, :uid, :t, :is_spam, :action, :forced_action, :mid, :user, :smtp_from, :smtp_rcpts, :subject, :asn, :ipnet, :country, :ssp, :len, :time_real, :time_virtual, :dns_req, :digest, :mime_rcpts, :filename, :qid, :settings_id, :cursor
	)
	`)
	if err != nil {
		j.Err(err)
		return
	}
	var l *rlog.Log
	var ok bool
	ct := 0
	for {
		select {
		case <-gg.Done():
			return
		case l, ok = <-c:
			if !ok {
				defer j.Info("count:", ct)
				return
			}
			ct++
			user := &sql.NullString{l.User, true}
			if len(user.String) == 0 {
				user.Valid = false
			}
			filename := &sql.NullString{l.Filename, true}
			if len(filename.String) == 0 {
				filename.Valid = false
			}
			qid := &sql.NullString{l.Qid, true}
			if len(qid.String) == 0 {
				qid.Valid = false
			}
			if _, err := ins.ExecContext(gg,
				sql.Named(`score`, l.Score),
				sql.Named(`max_score`, l.Max_score),
				sql.Named(`mfrom`, l.From),
				sql.Named(`ip`, l.Ip.String()),
				sql.Named(`uid`, l.Uid),
				sql.Named(`t`, l.T.Format(`2006-01-02 15:04:05.000-07:00`)),
				sql.Named(`is_spam`, l.Is_spam),
				sql.Named(`action`, l.Action),
				sql.Named(`forced_action`, l.Forced_action),
				sql.Named(`mid`, l.Mid),
				sql.Named(`user`, user),
				sql.Named(`smtp_from`, l.Smtp_from),
				sql.Named(`smtp_rcpts`, l.Smtp_rcpts),
				sql.Named(`subject`, l.Subject),
				sql.Named(`asn`, l.Asn),
				sql.Named(`ipnet`, l.Ipnet),
				sql.Named(`country`, l.Country),
				sql.Named(`ssp`, l.Ssp),
				sql.Named(`len`, l.Len),
				sql.Named(`time_real`, l.Time_real.String()),
				sql.Named(`time_virtual`, l.Time_virtual.String()),
				sql.Named(`dns_req`, l.Dns_req),
				sql.Named(`digest`, l.Digest),
				sql.Named(`mime_rcpts`, l.Mime_rcpts),
				sql.Named(`filename`, filename),
				sql.Named(`qid`, l.Qid),
				sql.Named(`settings_id`, l.Settings_id),
				sql.Named(`cursor`, []byte(l.Cursor)),
			); err != nil {
				j.Err(err)
				return
			}
		}
	}
}
