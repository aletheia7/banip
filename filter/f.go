// Copyright 2018 aletheia7. All rights reserved. Use of this source code is
// governed by a BSD-2-Clause license that can be found in the LICENSE file.
package filter

import (
	"bytes"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/aletheia7/sd"
	"path"
	"regexp"
	"strings"
	"text/template"
)

var j = sd.New()

const (
	ipv4var = `{{.Ipv4}}`
	ipv4re  = `(?P<ipv4>\d{1,3}(?:[.]\d{1,3}){3}){1}`
)

type Filter struct {
	Name     string
	Enabled  bool
	Action   string
	Tag      []string
	Re       []*regexp.Regexp
	Testdata [][]byte
}

func New(fn string) (*Filter, error) {
	if ext := path.Ext(fn); ext != ".toml" {
		e := fmt.Errorf("missing toml file: %v", fn)
		j.Err(e)
		return nil, e
	}
	conf := &Filter{
		Name:     strings.Split(path.Base(fn), ".toml")[0],
		Re:       make([]*regexp.Regexp, 0),
		Testdata: [][]byte{},
	}
	_, err := toml.DecodeFile(fn, conf)
	if err != nil {
		j.Err("decode:", err)
		return nil, err
	}
	return conf, nil
}

func (o *Filter) UnmarshalTOML(data interface{}) error {
	j.Info(o.Name)
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
			case []string:
				o.Tag = t
			default:
				return fmt.Errorf("missing syslog_identifier: %v", v)
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
			o.Testdata = make([][]byte, 0, len(a))
			for i, dv := range a {
				s, ok := dv.(string)
				if !ok {
					return fmt.Errorf("testdata[%v] is not a string:", i, dv)
				}
				o.Testdata = append(o.Testdata, []byte(s))
			}
		default:
			e := fmt.Errorf("unknown key: %v, v: %#v\n", k, v)
			j.Err(e)
			return e
		}
	}
	return nil
}
