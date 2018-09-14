package nft

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

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
	for _, cmd := range []*exec.Cmd{
		exec.Command("nft", "add", "table", o.Family, o.Table),
		exec.Command("nft", "add", "set", o.Family, o.Table, o.Set, `{ type ipv4_addr; }`),
		exec.Command("nft", "add", "chain", o.Family, o.Table, `input`, `{ type filter hook ingress device `+device+` priority 0; policy accept; }`),
		exec.Command("nft", "add", "rule", o.Family, o.Table, `input`, `ip saddr @`+set+` drop comment "`+Rule_marker+`"`),
	} {
		if b, err := cmd.CombinedOutput(); err != nil {
			return nil, &Err{Err: err, Args: cmd.Args, Output: b}
		}
	}
	o.Flush_set()
	return o, nil
}

func (o *Table) remove_previous() {
	if b, err := exec.Command("nft", "-a", "list chain netdev filter input").Output(); err == nil {
		if m := regexp.MustCompile(`"`+Rule_marker+`" # handle (\d+)`).FindAllSubmatch(b, -1); m != nil {
			for _, line := range m {
				if 2 <= len(line) {
					exec.Command("nft", "delete", "rule", "netdev", "filter", "input", "handle", string(line[1])).Run()
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
