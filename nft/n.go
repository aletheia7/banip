// Copyright 2018 aletheia7. All rights reserved. Use of this source code is
// governed by a BSD-2-Clause license that can be found in the LICENSE file.

package nft

import (
	"fmt"
	"github.com/aletheia7/sd"
	"os/exec"
	"regexp"
	"strings"
)

var j = sd.New()

const Rule_marker = " ☢ ban ☢ "

type Err struct {
	Err    error
	Args   []string
	Output []byte
}

type Table struct {
	Family string
	Table  string
	Set    string
}

func New_table(family, table, set, device string) (*Table, *Err) {
	o := &Table{Family: family, Table: table, Set: set}
	o.remove_previous()
	re := `(?m)\s+ct state invalid drop # handle (\d+)$`
	add_handle := o.get_insertion_handle(re)
	if len(add_handle) == 0 {
		return nil, &Err{Err: fmt.Errorf("cannot find handle for re: %v", re), Args: []string{}, Output: []byte{}}
	}
	for _, cmd := range []*exec.Cmd{
		// exec.Command("nft", "add", "table", o.Family, o.Table),
		exec.Command("nft", "add", "set", o.Family, o.Table, o.Set, `{ type ipv4_addr; }`),
		// exec.Command("nft", "add", "chain", o.Family, o.Table, `input`, `{ type filter hook ingress device `+device+` priority 0; policy accept; }`),
		exec.Command("nft", "add", "rule", o.Family, o.Table, `input`, `handle`, add_handle, `ip saddr @`+set+` drop comment "`+Rule_marker+`"`),
	} {
		if b, err := cmd.CombinedOutput(); err != nil {
			return nil, &Err{Err: err, Args: cmd.Args, Output: b}
		}
	}
	o.Flush_set()
	return o, nil
}

func (o *Table) get_insertion_handle(re string) string {
	if b, err := exec.Command("nft", "-a", "list", "chain", o.Family, o.Table, "input").Output(); err == nil {
		if m := regexp.MustCompile(re).FindAllSubmatch(b, -1); m != nil {
			if len(m) == 1 && len(m[0]) == 2 {
				return string(m[0][1])
			}
		}
	}
	return ``
}

func (o *Table) remove_previous() {
	if b, err := exec.Command("nft", "-a", "list", "chain", o.Family, o.Table, "input").Output(); err == nil {
		if m := regexp.MustCompile(`"`+Rule_marker+`" # handle (\d+)`).FindAllSubmatch(b, -1); m != nil {
			for _, line := range m {
				if 2 <= len(line) {
					exec.Command("nft", "delete", "rule", o.Family, o.Table, "input", "handle", string(line[1])).Run()
				}
			}
		}
	}
}

func (o *Table) Delete() error {
	cmd := exec.Command("nft", "delete", "table", o.Family, o.Table)
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %v: %s", cmd.Args, err, b)
	}
	return nil
}

func (o *Table) Flush_set() error {
	cmd := exec.Command("nft", "flush", "set", o.Family, o.Table, o.Set)
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %v: %s", cmd.Args, err, b)
	}
	return nil
}

func (o *Table) Add_set(ip ...string) error {
	cmd := exec.Command("nft", "add", "element", o.Family, o.Table, o.Set, `{ `+strings.Join(ip, `,`)+` }`)
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %v: %s", cmd.Args, err, b)
	}
	return nil
}
