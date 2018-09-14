// Copyright 2018 aletheia7. All rights reserved. Use of this source code is
// governed by a BSD-2-Clause license that can be found in the LICENSE file.

package filter

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/aletheia7/gogroup"
	"github.com/aletheia7/mbus"
	"github.com/aletheia7/sd"
	"path"
	"regexp"
	"strings"
	"text/template"
)

var (
	j        = sd.New()
	ipv4b    = []byte{36, 105, 112, 118, 52} // $ipv4
	pmatched = flag.Bool("pmatched", false, "print matched w/ -test")
	pmissed  = flag.Bool("pmissed", false, "print missed w/ -test")
)

const (
	T_msg   = "msg"
	ipv4var = `{{.Ipv4}}`
	ipv4re  = `(?P<ipv4>\d{1,3}(?:[.]\d{1,3}){3}){1}`
)

type Filter struct {
	gg       *gogroup.Group
	bus      *mbus.Bus
	c        chan *mbus.Msg
	Name     string
	Enabled  bool
	Action   string
	Tag      []string
	Re       []*regexp.Regexp
	testdata [][]byte
	subs     []string
}

func New(gg *gogroup.Group, bus *mbus.Bus, fn string) (*Filter, error) {
	if ext := path.Ext(fn); ext != ".toml" {
		e := fmt.Errorf("missing toml file: %v", fn)
		j.Err(e)
		return nil, e
	}
	o := &Filter{
		gg:       gg,
		bus:      bus,
		c:        make(chan *mbus.Msg, 256),
		Name:     strings.Split(path.Base(fn), ".toml")[0],
		Re:       make([]*regexp.Regexp, 0),
		testdata: [][]byte{},
	}
	_, err := toml.DecodeFile(fn, o)
	if err != nil {
		j.Err("decode:", err)
		return nil, err
	}
	o.subs = make([]string, 0, len(o.Tag)+1)
	o.subs = append(o.subs, T_msg)
	for _, t := range o.Tag {
		o.subs = append(o.subs, t)
	}
	o.bus.Subscribe(o.c, o.subs...)
	go o.run()
	return o, nil
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
			}
		}
	}
}

func (o *Filter) Testdata() {
	defer o.gg.Cancel()
	matched := 0
	total := 0
	for _, t := range o.testdata {
		select {
		case <-o.gg.Done():
			return
		default:
			total++
			for _, re := range o.Re {
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
		case "re":
			a, ok := v.([]interface{})
			if !ok {
				return fmt.Errorf("not an array:", k)
			}
			o.Re = make([]*regexp.Regexp, 0, len(a))
			for i, rev := range a {
				s, ok := rev.(string)
				if !ok {
					return fmt.Errorf("re[%v] is not a string:", i, rev)
				}
				if -1 == strings.Index(s, ipv4var) {
					return fmt.Errorf("missing in re: %v %s", ipv4var, s)
				}
				t, err := template.New(``).Parse(s)
				if err != nil {
					return fmt.Errorf("cannot make template:", err, s)
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
		case "testdata":
			a, ok := v.([]interface{})
			if !ok {
				return fmt.Errorf("not an array:", k)
			}
			o.testdata = make([][]byte, 0, len(a))
			for i, dv := range a {
				s, ok := dv.(string)
				if !ok {
					return fmt.Errorf("testdata[%v] is not a string:", i, dv)
				}
				o.testdata = append(o.testdata, []byte(s))
			}
		default:
			e := fmt.Errorf("unknown key: %v, v: %#v\n", k, v)
			j.Err(e)
			return e
		}
	}
	return nil
}
