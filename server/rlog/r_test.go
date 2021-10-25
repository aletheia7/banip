package rlog

import (
	"io/ioutil"
	"os"
	"regexp"
	"testing"

	"github.com/aletheia7/gogroup/v2"
)

var gg = gogroup.New(gogroup.Add_signals(gogroup.Unix))

func Test_read(t *testing.T) {
	const fn = `testdata/t.json`
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		t.Fatal(err)
	}
	proxy_re := regexp.MustCompile(`proxy; rspamd_task_write_log: α`)
	expect_ct := len(proxy_re.FindAllSubmatch(b, -1))
	b = nil
	fp, err := os.Open(`testdata/t.json`)
	if err != nil {
		j.Err(err)
		return
	}
	defer fp.Close()
	c := New_listener(gg, fp)
	var ok bool
	ct := 0
	defer func() {
		t.Logf("expected: %v, rx: %v", expect_ct, ct)
		if ct != expect_ct {
			t.Fatalf("fn lines != expected: %v vs %v", expect_ct, ct)
		}
	}()
	for {
		select {
		case <-gg.Done():
			return
		case _, ok = <-c:
			if !ok {
				return
			}
			ct++
		}
	}
}
