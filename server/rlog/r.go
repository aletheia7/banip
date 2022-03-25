package rlog

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aletheia7/banip/server/rlog/jep"
	"github.com/aletheia7/gogroup"
	"github.com/aletheia7/sd/v6"
)

var (
	j = sd.New()
	// j      = sd.New(sd.Set_default_disable_journal(true), sd.Set_default_writer_stdout())
	row_re = regexp.MustCompile(`^(?:\<(?P<unique>[[:alnum:]]+)\>; (?P<log_type>[^;]+); rspamd_task_write_log: α )|(?:(?P<key>\w+)(?: 𐅀 )(?P<value>[^|]*))(?:(?: \| )|(?: ω))`)
	ssp_re = regexp.MustCompile(`(?P<symbol>\w+)\((?P<score>[^)]+)\)\{(?P<params>[^}]*)\},?`)
	asn_re = regexp.MustCompile(`^asn:(?P<asn>\d+), ipnet:(?P<ipnet>[^,]+), country:(?P<country>[^;]+);$`)
)

const (
	read_max_size = 100_000_000
	Log_chan_size = 1_000
)

type Log struct {
	Uid                 string // Brackets ommitted
	T                   time.Time
	Is_spam             bool
	Action              string
	Score, Max_score    float64
	Ip                  net.IP
	User                string
	Smtp_from           string
	Smtp_rcpts          string
	Ssp                 string // json: symbols_scores_params
	Len                 int
	Time_real           time.Duration
	Time_virtual        time.Duration
	Dns_req             int
	Digest              string
	Mime_rcpts          string
	Filename            string
	Forced_action       string
	Mid                 string // Brackets ommitted
	Qid                 string
	Settings_id         string
	From                string
	Subject             string
	Asn, Ipnet, Country string
	Raw                 string
	Cursor              string
}

func (o *Log) Sqlt() string {
	return o.T.Format(`2006-01-02 15:04:05.000-07:00`)
}

type Ssp struct {
	Score  float64 `json:"score,omitempty"`
	Params string  `json:"params,omitempty"`
}

func (o *Ssp) to_json(symbol string) []byte {
	buf := bytes.NewBufferString(`"` + symbol + `":`)
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	enc.Encode(o)
	// remove \n from Encode
	return buf.Bytes()[:buf.Len()-1]
}

func New_listener(gg *gogroup.Group, r io.Reader) (c chan *Log) {
	c = make(chan *Log, Log_chan_size)
	go func() {
		var (
			err       error
			re_result [][]string
			action    = map[string]string{
				`no action`:   `no`,
				`add header`:  `junk`,
				`reject`:      `reject`,
				`greylist`:    `grey`,
				`soft reject`: `soft`,
			}
			ok         bool
			entry      jep.Entry
			scanner, e = jep.New(gg, r, jep.Buffer(100_000))
			t          string
		)
		defer close(c)
		for {
			select {
			case <-gg.Done():
				return
			case entry, ok = <-scanner:
				if !ok {
					if err = e.Error(); err != nil {
						j.Err(err)
					}
					return
				}
			}
			var t_64 int64
			if t, ok = entry[`_SOURCE_REALTIME_TIMESTAMP`]; ok {
				t_64, err = strconv.ParseInt(t, 10, 64)
			} else {
				if t, ok = entry[`__REALTIME_TIMESTAMP`]; ok {
					t_64, err = strconv.ParseInt(t, 10, 64)
				} else {
					j.Warning("missing journal_rts|rt")
					continue
				}
			}
			if err != nil {
				j.Warning(err)
				continue
			}
			l := &Log{
				T:      time.Unix(0, (t_64*int64(time.Microsecond))/int64(time.Nanosecond)).Local().Truncate(time.Millisecond),
				Cursor: entry[`__CURSOR`],
				// Raw: m[bpos+len(rstart) : epos],
			}
			if re_result = row_re.FindAllStringSubmatch(entry[`MESSAGE`], -1); re_result == nil {
				continue
			}
			if l.Uid = re_result[0][row_re.SubexpIndex("unique")]; len(l.Uid) == 0 {
				j.Warningf("regexp failed for cursor: %v", l.Cursor)
				continue
			}
			switch re_result[0][row_re.SubexpIndex("log_type")] {
			case `proxy`:
			case `csession`:
				// These are learn_ham and learn_spam submissions
				continue
			default:
				j.Warningf("invalid log_type for cursor: %v %v\n", re_result[0][row_re.SubexpIndex("log_type")], l.Cursor)
				continue
			}
		next_row:
			for _, kv := range re_result[1:] {
				if len(kv[row_re.SubexpIndex(`value`)]) == 0 {
					continue
				}
				switch kv[row_re.SubexpIndex(`key`)] {
				case `is_spam`:
					if l.Is_spam, err = strconv.ParseBool(kv[row_re.SubexpIndex(`value`)]); err != nil {
						j.Warning(err)
					}
				case `action`:
					l.Action = action[kv[row_re.SubexpIndex(`value`)]]
				case `scores`:
					as := strings.Split(kv[row_re.SubexpIndex(`value`)], `/`)
					if len(as) != 2 {
						j.Warning("scores != 2", kv[row_re.SubexpIndex(`value`)])
						continue next_row
					}
					if l.Score, err = strconv.ParseFloat(as[0], 64); err != nil {
						j.Warning(kv[row_re.SubexpIndex(`value`)], err)
					}
					if l.Max_score, err = strconv.ParseFloat(as[1], 64); err != nil {
						j.Warning(kv[row_re.SubexpIndex(`value`)], err)
					}
				case `ip`:
					l.Ip = net.ParseIP(kv[row_re.SubexpIndex(`value`)])
				case `user`:
					l.User = kv[row_re.SubexpIndex(`value`)]
				case `smtp_from`:
					l.Smtp_from = kv[row_re.SubexpIndex(`value`)]
				case `smtp_rcpts`:
					l.Smtp_rcpts = kv[row_re.SubexpIndex(`value`)]
				case `symbols_scores_params`:
					// Used to preserve rspamd symbol order. go map loses symbol order
					a_ssp := make([][]byte, 0, 10)
					var ma [][]string
					var masn []string
					var ssp *Ssp
					var symbol string
					ma = ssp_re.FindAllStringSubmatch(kv[row_re.SubexpIndex(`value`)], -1)
					for _, m := range ma {
						switch symbol = m[ssp_re.SubexpIndex("symbol")]; symbol {
						case `ASN`:
							masn = asn_re.FindStringSubmatch(m[ssp_re.SubexpIndex("params")])
							if masn == nil {
								j.Warningf("asn does not match regexp: %v %v", asn_re.String(), m[ssp_re.SubexpIndex("params")])
							} else {
								l.Asn = masn[asn_re.SubexpIndex("asn")]
								l.Ipnet = masn[asn_re.SubexpIndex("ipnet")]
								l.Country = masn[asn_re.SubexpIndex("country")]
							}
						default:
							ssp = &Ssp{}
							ssp.Score, _ = strconv.ParseFloat(m[ssp_re.SubexpIndex("score")], 64)
							if len(m) == 4 {
								ssp.Params = m[ssp_re.SubexpIndex("params")]
							}
							a_ssp = append(a_ssp, ssp.to_json(symbol))
						}
					}
					l.Ssp = `{` + string(bytes.Join(a_ssp, []byte{','})) + `}`
				case `len`:
					if l.Len, err = strconv.Atoi(kv[row_re.SubexpIndex(`value`)]); err != nil {
						j.Warning(err)
					}
				case `time_real`:
					if l.Time_real, err = time.ParseDuration(kv[row_re.SubexpIndex(`value`)]); err != nil {
						j.Warning(kv[row_re.SubexpIndex(`value`)], err)
					}
				case `time_virtual`:
					if l.Time_virtual, err = time.ParseDuration(kv[row_re.SubexpIndex(`value`)]); err != nil {
						j.Warning(kv[row_re.SubexpIndex(`value`)], err)
					}
				case `dns_req`:
					if l.Dns_req, err = strconv.Atoi(kv[row_re.SubexpIndex(`value`)]); err != nil {
						j.Warning(err)
					}
				case `digest`:
					l.Digest = kv[row_re.SubexpIndex(`value`)]
				case `mime_rcpts`:
					l.Mime_rcpts = kv[row_re.SubexpIndex(`value`)]
				case `filename`:
					l.Filename = kv[row_re.SubexpIndex(`value`)]
				case `forced_action`:
					l.Forced_action = kv[row_re.SubexpIndex(`value`)]
				case `mid`:
					if strings.HasPrefix(kv[row_re.SubexpIndex(`value`)], `<`) && strings.HasSuffix(kv[row_re.SubexpIndex(`value`)], `>`) {
						l.Mid = kv[row_re.SubexpIndex(`value`)][1 : len(kv[row_re.SubexpIndex(`value`)])-1]
					} else {
						l.Mid = kv[row_re.SubexpIndex(`value`)]
					}
				case `qid`:
					l.Qid = kv[row_re.SubexpIndex(`value`)]
				case `settings_id`:
					l.Settings_id = kv[row_re.SubexpIndex(`value`)]
				case `from`:
					l.From = kv[row_re.SubexpIndex(`value`)]
				case `subject`:
					l.Subject = kv[row_re.SubexpIndex(`value`)]
				}
			}
			c <- l
		}
	}()
	return
}
