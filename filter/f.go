// Copyright 2018 aletheia7. All rights reserved. Use of this source code is
// governed by a BSD-2-Clause license that can be found in the LICENSE file.

package filter

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"path"
	"regexp"
	"strings"
	"text/template"

	"github.com/BurntSushi/toml"
	"github.com/aletheia7/banip/list"
	br "github.com/aletheia7/banip/rbl"
	"github.com/aletheia7/gogroup"
	"github.com/aletheia7/mbus"
	"github.com/aletheia7/sd/v6"
)

var (
	j        = sd.New()
	pmatched = flag.Bool("pmatched", false, "print matched w/ -test")
	pmissed  = flag.Bool("pmissed", false, "print missed w/ -test")
	pignored = flag.Bool("pignored", false, "print ignored w/ -test")
	Rbls     = []string{}
)

const (
	T_test  = `test`
	T_bl    = `bl`
	T_wl    = `wl`
	ipv4var = `{{.Ipv4}}`
	ipv4re  = `(?P<ipv4>\d{1,3}(?:[.]\d{1,3}){3}){1}`
	ipv4    = `$ipv4`
)

type Action struct {
	Toml      string
	Ip        string
	Msg       string
	Check_rbl bool
	Rbl       interface{}
}

type Filter struct {
	parent, gg        *gogroup.Group
	bus               *mbus.Bus
	c                 chan *mbus.Msg
	Name              string
	Enabled           bool
	Action            string
	Tag               []string
	Re, Ignore        []*regexp.Regexp
	Rbl_use, Rbl_must bool
	testdata          []string
	subs              []string
	matched           int
	matched_u         map[string]bool
	ignored           int
	total             int
	list              *list.WB
	rbl               *br.Search
}

type Get_it interface {
	In_list(ip net.IP) bool
}

func New(gg *gogroup.Group, bus *mbus.Bus, fn string, list *list.WB, rbls []string) (*Filter, error) {
	if ext := path.Ext(fn); ext != ".toml" {
		e := fmt.Errorf("missing toml file: %v", fn)
		j.Err(e)
		return nil, e
	}
	o := &Filter{
		parent:    gg,
		gg:        gogroup.New(gogroup.With_cancel(gg)),
		bus:       bus,
		c:         make(chan *mbus.Msg, 256),
		Name:      strings.Split(path.Base(fn), ".toml")[0],
		Re:        make([]*regexp.Regexp, 0),
		Ignore:    make([]*regexp.Regexp, 0),
		testdata:  []string{},
		matched_u: map[string]bool{},
		list:      list,
		rbl:       br.New(gg, rbls),
	}
	_, err := toml.DecodeFile(fn, o)
	if err != nil {
		j.Err("decode:", err)
		return nil, err
	}
	o.subs = make([]string, 0, len(o.Tag)+1)
	o.subs = append(o.subs, o.Tag...)
	o.subs = append(o.subs, T_test)
	o.bus.Subscribe(o.c, o.subs...)
	go o.run()
	return o, nil
}

// Call Stop() to shutdown
func (o *Filter) Stop() {
	o.gg.Cancel()
}

func (o *Filter) run() {
	key := o.gg.Register()
	defer o.gg.Unregister(key)
	defer o.bus.Unsubscribe(o.c, o.subs...)
	for {
		select {
		case <-o.gg.Done():
			return
		case in := <-o.c:
			switch in.Topic {
			case T_test:
				o.test(in)
			default:
				o.check(in)
			}
		}
	}
}

func (o *Filter) Testdata() {
	if o.Rbl_must {
		o.Rbl_must = false
		j.Info("setting rbl_must = false testdata only")
	}
	for _, t := range o.testdata {
		o.c <- mbus.New_msg(T_test, t)
	}
	o.c <- mbus.New_msg(T_test, nil)
}

func (o *Filter) check(in *mbus.Msg) {
	select {
	case <-o.gg.Done():
		return
	default:
		if msg, ok := in.Data.(string); ok {
			for _, re := range o.Re {
				if ip := re.ExpandString(nil, ipv4, msg, re.FindStringSubmatchIndex(msg)); ip != nil {
					ipnet := net.ParseIP(string(ip))
					if o.list.W.Lookup(ipnet) || o.list.B.Lookup(ipnet) {
						return
					}
					if o.Rbl_must {
						select {
						case <-o.gg.Done():
							return
						default:
							if a := o.rbl.Lookup(ipnet, true); 0 < len(a) {
								o.bus.Pub(T_bl, &Action{Toml: o.Name, Ip: string(ip), Msg: msg, Rbl: a[0]})
								return
							}
						}
					} else {
						o.bus.Pub(T_bl, &Action{Toml: o.Name, Ip: string(ip), Msg: msg, Check_rbl: o.Rbl_use})
						return
					}
				}
			}
		}
	}
}

func (o *Filter) test(in *mbus.Msg) {
	select {
	case <-o.gg.Done():
		return
	default:
		switch msg := in.Data.(type) {
		case nil:
			j.Infof("total: matched: %v (%v), ignored: %v, missed: %v, total: %v\n", o.matched, len(o.matched_u), o.ignored, o.total-o.matched-o.ignored, o.total)
			// Call parent to shutdown app gracefully
			o.parent.Cancel()
			return
		case string:
			o.total++
			for _, re := range o.Re {
				s := re.ExpandString(nil, ipv4, msg, re.FindStringSubmatchIndex(msg))
				if s != nil {
					if o.Rbl_must {
						ipnet := net.ParseIP(string(s))
						if o.list.W.Lookup(ipnet) || o.list.B.Lookup(ipnet) {
							o.matched++
							o.matched_u[string(s)] = true
							if *pmatched {
								j.Infof("matched: %s %v\n%v\n", s, re.String(), msg)
							}
							return
						}
						select {
						case <-o.gg.Done():
							return
						default:
							if a := o.rbl.Lookup(ipnet, true); 0 < len(a) {
								o.matched++
								o.matched_u[string(s)] = true
								if *pmatched {
									j.Infof("matched: %s %v\n%v\n", s, re.String(), msg)
								}
								return
							}
						}
					} else {
						o.matched++
						o.matched_u[string(s)] = true
						if *pmatched {
							j.Infof("matched: %s %v\n%v\n", s, re.String(), msg)
						}
						return
					}
				}
			}
			for _, re := range o.Ignore {
				if re.MatchString(msg) {
					o.ignored++
					if *pignored {
						j.Infof("ignored: %s\n", re.String())
					}
					return
				}
			}
			if *pmissed {
				j.Infof("missed: %s\n", msg)
			}
		}
	}
}

func (o *Filter) UnmarshalTOML(data interface{}) error {
	m := data.(map[string]interface{})
	var ok bool
	for k, v := range m {
		switch strings.ToLower(k) {
		case "enabled":
			if o.Enabled, ok = v.(bool); !ok {
				return fmt.Errorf("missing enabled: %v", v)
			}
		case "action":
			if o.Action, ok = v.(string); !ok {
				return fmt.Errorf("missing action: %v", v)
			}
		case "syslog_identifier":
			switch t := v.(type) {
			case string:
				o.Tag = []string{t}
			case []interface{}:
				o.Tag = make([]string, 0, len(t))
				for _, i := range t {
					if s, ok := i.(string); ok {
						o.Tag = append(o.Tag, s)
					} else {
						return fmt.Errorf("unknown syslog_identifier: %T %v", t, t)
					}
				}
			default:
				return fmt.Errorf("unknown syslog_identifier: %T %v", t, t)
			}
		case "rbl_use":
			if t, ok := v.(bool); ok {
				o.Rbl_use = t
			} else {
				return fmt.Errorf("unknown rbl_use: %T %v", t, t)
			}
		case "rbl_must":
			if t, ok := v.(bool); ok {
				o.Rbl_must = t
			} else {
				return fmt.Errorf("unknown rbl_must: %T %v", t, t)
			}
		case "re":
			a, ok := v.([]interface{})
			if !ok {
				return fmt.Errorf("not an array: %v", k)
			}
			o.Re = make([]*regexp.Regexp, 0, len(a))
			for i, rev := range a {
				s, ok := rev.(string)
				if !ok {
					return fmt.Errorf("re[%v] is not a string: %v", i, rev)
				}
				if !strings.Contains(s, ipv4var) {
					return fmt.Errorf("missing in re: %v %s", ipv4var, s)
				}
				t, err := template.New(``).Parse(s)
				if err != nil {
					return fmt.Errorf("cannot make template: %v, %v", err, s)
				}
				var reb bytes.Buffer
				if err := t.Execute(&reb, map[string]string{"Ipv4": ipv4re}); err != nil {
					j.Err(err)
					return err
				}
				if re, err := regexp.Compile(reb.String()); err == nil {
					o.Re = append(o.Re, re)
				} else {
					return fmt.Errorf("%v: %v", err, reb.String())
				}
			}
		case "ignore":
			a, ok := v.([]interface{})
			if !ok {
				return fmt.Errorf("not an array: %v", k)
			}
			o.Ignore = make([]*regexp.Regexp, 0, len(a))
			for i, rev := range a {
				s, ok := rev.(string)
				if !ok {
					return fmt.Errorf("re[%v] is not a string: %v", i, rev)
				}
				if ignore, err := regexp.Compile(s); err == nil {
					o.Ignore = append(o.Ignore, ignore)
				} else {
					return fmt.Errorf("%v: %v", err, s)
				}
			}
		case "testdata":
			a, ok := v.([]interface{})
			if !ok {
				return fmt.Errorf("not an array: %v", k)
			}
			o.testdata = make([]string, 0, len(a))
			for i, dv := range a {
				s, ok := dv.(string)
				if !ok {
					return fmt.Errorf("testdata[%v] is not a string: %v", i, dv)
				}
				o.testdata = append(o.testdata, s)
			}
		default:
			e := fmt.Errorf("unknown key: %v, v: %#v", k, v)
			j.Err(e)
			return e
		}
	}
	return nil
}
