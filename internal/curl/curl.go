// Package curl converts cURL commands (bash/zsh, Windows cmd, PowerShell/curl.exe)
// into a Burp-style request.
package curl

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"curlp/internal/request"
)

// Result is a cURL command converted to a request.
type Result struct {
	Method   string      `json:"method"`
	Target   string      `json:"target"`
	Path     string      `json:"path"`
	Headers  [][2]string `json:"headers"`
	Body     string      `json:"body"`
	Insecure bool        `json:"insecure"`
	Follow   bool        `json:"follow"`
	Timeout  int         `json:"timeout"`
	Raw      string      `json:"raw"`
	Warnings []string    `json:"warnings"`
}

const (
	shPosix = iota
	shCmd
	shPowerShell
)

var (
	reCmd   = regexp.MustCompile(`\^\r?\n|\^"`)
	reCmdNL = regexp.MustCompile(`\^\r?\n`)
	reCaret = regexp.MustCompile(`\^(.)`)
	reBSNL  = regexp.MustCompile(`\\\r?\n`)
	reBTNL  = regexp.MustCompile("`\\r?\\n")
)

func set(v ...string) map[string]bool {
	m := make(map[string]bool, len(v))
	for _, s := range v {
		m[s] = true
	}
	return m
}

// Options that consume a value and change the request.
var withArg = set("-X", "--request", "-H", "--header", "-d", "--data", "--data-raw", "--data-binary", "--data-ascii",
	"--data-urlencode", "--json", "-F", "--form", "--form-string", "-u", "--user", "-b", "--cookie", "-A", "--user-agent",
	"-e", "--referer", "--url", "-m", "--max-time", "--oauth2-bearer")

// Options that consume a value but are irrelevant for replaying a request.
var skipArg = set("-o", "--output", "-w", "--write-out", "-x", "--proxy", "--max-redirs", "--connect-timeout", "-T", "--upload-file",
	"--cacert", "--cert", "-E", "--key", "--resolve", "--retry", "-K", "--config", "--proto", "--interface", "-c", "--cookie-jar",
	"-D", "--dump-header", "--limit-rate", "--proxy-user", "-U", "--connect-to", "--dns-servers", "--cert-type", "--keepalive-time")

// Ignored options worth reporting, because the replay will differ from the real command.
var warnIgnored = set("-x", "--proxy", "-T", "--upload-file", "--cacert", "--cert", "-E", "--key", "--resolve", "--connect-to", "-K", "--config")

/* ---------------- tokenizer ---------------- */

func hexVal(rs []rune, i, n int) (v, used int) {
	for used < n && i+used < len(rs) {
		d := strings.IndexRune("0123456789abcdef", unicode.ToLower(rs[i+used]))
		if d < 0 {
			break
		}
		v = v*16 + d
		used++
	}
	return
}

func tokenize(src string, mode int) []string {
	var out []string
	var cur strings.Builder
	has := false
	rs := []rune(src)
	push := func() {
		if has {
			out = append(out, cur.String())
			cur.Reset()
			has = false
		}
	}
	for i := 0; i < len(rs); {
		c := rs[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			push()
			i++

		case c == '\'':
			i++
			has = true
			for i < len(rs) {
				if rs[i] == '\'' {
					if mode == shPowerShell && i+1 < len(rs) && rs[i+1] == '\'' { // PowerShell: '' is a literal quote
						cur.WriteRune('\'')
						i += 2
						continue
					}
					break
				}
				cur.WriteRune(rs[i])
				i++
			}
			i++ // closing quote

		case c == '$' && mode == shPosix && i+1 < len(rs) && rs[i+1] == '\'': // ANSI-C quoting: $'...'
			i += 2
			has = true
			for i < len(rs) && rs[i] != '\'' {
				if rs[i] == '\\' && i+1 < len(rs) {
					n := rs[i+1]
					i += 2
					switch n {
					case 'n':
						cur.WriteByte('\n')
					case 't':
						cur.WriteByte('\t')
					case 'r':
						cur.WriteByte('\r')
					case 'x': // a single byte: \xc3\xa9 forms valid UTF-8
						if v, k := hexVal(rs, i, 2); k > 0 {
							cur.WriteByte(byte(v))
							i += k
						} else {
							cur.WriteString(`\x`)
						}
					case 'u':
						if v, k := hexVal(rs, i, 4); k > 0 {
							cur.WriteRune(rune(v))
							i += k
						} else {
							cur.WriteString(`\u`)
						}
					default:
						cur.WriteRune(n)
					}
					continue
				}
				cur.WriteRune(rs[i])
				i++
			}
			i++

		case c == '"':
			i++
			has = true
			for i < len(rs) && rs[i] != '"' {
				if mode == shPowerShell && rs[i] == '`' && i+1 < len(rs) {
					n := rs[i+1]
					i += 2
					switch n {
					case 'n':
						cur.WriteByte('\n')
					case 't':
						cur.WriteByte('\t')
					case 'r':
						cur.WriteByte('\r')
					default:
						cur.WriteRune(n)
					}
					continue
				}
				if mode != shPowerShell && rs[i] == '\\' && i+1 < len(rs) && strings.ContainsRune("\"\\$`", rs[i+1]) {
					cur.WriteRune(rs[i+1])
					i += 2
					continue
				}
				cur.WriteRune(rs[i])
				i++
			}
			i++

		case c == '\\' && mode != shPowerShell:
			if i+1 < len(rs) {
				cur.WriteRune(rs[i+1])
				has = true
			}
			i += 2

		case c == '`' && mode == shPowerShell:
			if i+1 < len(rs) {
				cur.WriteRune(rs[i+1])
				has = true
			}
			i += 2

		default:
			cur.WriteRune(c)
			has = true
			i++
		}
	}
	push()
	return out
}

func detectShell(s string) int {
	switch {
	case reCmd.MatchString(s):
		return shCmd // Windows cmd "Copy as cURL": ^ line breaks and ^" escapes
	case reBTNL.MatchString(s) || strings.HasPrefix(strings.ToLower(s), "curl.exe"):
		return shPowerShell // backtick line breaks / curl.exe
	}
	return shPosix // bash, zsh, Chrome/Firefox/Burp "Copy as cURL"
}

/* ---------------- option parsing ---------------- */

type opts struct {
	method                          string
	urls                            []string
	headers                         [][2]string
	data, form                      []string
	get, head, insecure, follow, js bool
	timeout                         int
	user, bearer                    string
	warnings                        []string
}

func (o *opts) warn(format string, a ...any) { o.warnings = append(o.warnings, fmt.Sprintf(format, a...)) }

func urlenc(v string) string {
	if i := strings.Index(v, "="); i >= 0 {
		name := v[:i]
		if name != "" {
			name += "="
		}
		return name + url.QueryEscape(v[i+1:])
	}
	return url.QueryEscape(v)
}

func (o *opts) apply(f, v string) {
	switch f {
	case "-X", "--request":
		o.method = strings.ToUpper(v)
	case "-H", "--header":
		if strings.HasPrefix(v, "@") {
			o.warn("header file %s was not read", v)
			return
		}
		if i := strings.Index(v, ":"); i > 0 {
			o.headers = append(o.headers, [2]string{strings.TrimSpace(v[:i]), strings.TrimSpace(v[i+1:])})
		} else if strings.HasSuffix(v, ";") && len(v) > 1 { // "Name;" means: send an empty header
			o.headers = append(o.headers, [2]string{strings.TrimSuffix(v, ";"), ""})
		}
	case "-d", "--data", "--data-raw", "--data-binary", "--data-ascii":
		if f != "--data-raw" && strings.HasPrefix(v, "@") {
			o.warn("%s %s: file contents are not read, the reference is kept as text", f, v)
		}
		o.data = append(o.data, v)
	case "--data-urlencode":
		o.data = append(o.data, urlenc(v))
	case "--json":
		o.data = append(o.data, v)
		o.js = true
	case "-F", "--form", "--form-string":
		o.form = append(o.form, v)
	case "-u", "--user":
		o.user = v
	case "--oauth2-bearer":
		o.bearer = v
	case "-b", "--cookie":
		if strings.Contains(v, "=") {
			o.headers = append(o.headers, [2]string{"Cookie", v})
		} else {
			o.warn("cookie file %s was not read", v)
		}
	case "-A", "--user-agent":
		o.headers = append(o.headers, [2]string{"User-Agent", v})
	case "-e", "--referer":
		o.headers = append(o.headers, [2]string{"Referer", v})
	case "--url":
		o.urls = append(o.urls, v)
	case "-m", "--max-time":
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			o.timeout = int(math.Ceil(n))
		}
	case "-I", "--head":
		o.head = true
	case "-G", "--get":
		o.get = true
	case "-k", "--insecure":
		o.insecure = true
	case "-L", "--location":
		o.follow = true
	default:
		if warnIgnored[f] {
			o.warn("option %s is ignored (the request is replayed without it)", f)
		}
	}
}

func baseName(s string) string {
	if i := strings.LastIndexAny(s, `/\`); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// Parse converts a cURL command (bash, zsh, Windows cmd, PowerShell/curl.exe) to a request.
func Parse(input string) (*Result, error) {
	src := strings.TrimSpace(input)
	src = strings.TrimPrefix(src, "$ ")
	mode := detectShell(src)
	switch mode {
	case shCmd:
		src = reCaret.ReplaceAllString(reCmdNL.ReplaceAllString(src, " "), "$1")
	case shPowerShell:
		src = reBTNL.ReplaceAllString(src, " ")
	}
	if mode != shPowerShell {
		src = reBSNL.ReplaceAllString(src, " ")
	}

	t := tokenize(src, mode)
	if mode == shPowerShell { // curl.exe receives \" as a literal quote
		for i := range t {
			t[i] = strings.ReplaceAll(t[i], `\"`, `"`)
		}
	}
	if len(t) == 0 {
		return nil, errors.New("the command is empty")
	}
	if b := strings.ToLower(baseName(t[0])); b != "curl" && b != "curl.exe" {
		return nil, errors.New(`the command must start with "curl"`)
	}

	o := &opts{}
	for i := 1; i < len(t); i++ {
		a := t[i]
		switch {
		case a == "-" || a == "--":
			// stdin marker / end of options
		case strings.HasPrefix(a, "--"):
			name, val, hasVal := a, "", false
			if eq := strings.Index(a, "="); eq > 0 {
				name, val, hasVal = a[:eq], a[eq+1:], true
			}
			if withArg[name] || skipArg[name] {
				if !hasVal && i+1 < len(t) {
					i++
					val = t[i]
				}
				o.apply(name, val)
			} else {
				o.apply(a, "")
			}
		case len(a) > 1 && a[0] == '-':
			for k := 1; k < len(a); k++ { // clusters (-sSLk) and attached values (-XPOST, -H'A: b')
				f := "-" + string(a[k])
				if withArg[f] || skipArg[f] {
					val := a[k+1:]
					if val == "" && i+1 < len(t) {
						i++
						val = t[i]
					}
					o.apply(f, val)
					break
				}
				o.apply(f, "")
			}
		default:
			o.urls = append(o.urls, a)
		}
	}
	return o.build()
}

func (o *opts) build() (*Result, error) {
	if len(o.urls) == 0 {
		return nil, errors.New("no URL found in the command")
	}
	if len(o.urls) > 1 {
		o.warn("multiple URLs found, using the first one")
	}
	u := o.urls[0]
	if !request.SchemeRe.MatchString(u) {
		u = "http://" + u // curl's default scheme
	}
	pu, err := url.Parse(u)
	if err != nil || pu.Host == "" {
		return nil, fmt.Errorf("invalid URL: %s", o.urls[0])
	}

	headers := append([][2]string(nil), o.headers...)
	body := strings.Join(o.data, "&") // curl joins several -d values with &
	if o.get && body != "" {
		if pu.RawQuery != "" {
			pu.RawQuery += "&" + body
		} else {
			pu.RawQuery = body
		}
		body = ""
	}

	if len(o.form) > 0 {
		boundary := "----curlp" + strconv.FormatInt(time.Now().UnixNano(), 16)
		var b strings.Builder
		for _, f := range o.form {
			name, val, _ := strings.Cut(f, "=")
			disp := `form-data; name="` + name + `"`
			if strings.HasPrefix(val, "@") {
				file := val[1:]
				disp += `; filename="` + baseName(file) + `"`
				val = "<contents of " + file + ">"
			}
			b.WriteString("--" + boundary + "\r\nContent-Disposition: " + disp + "\r\n\r\n" + val + "\r\n")
		}
		b.WriteString("--" + boundary + "--\r\n")
		body = b.String()
		headers = append(headers, [2]string{"Content-Type", "multipart/form-data; boundary=" + boundary})
	}

	if o.user != "" {
		cred := o.user
		if !strings.Contains(cred, ":") {
			cred += ":"
		}
		headers = append(headers, [2]string{"Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(cred))})
	}
	if o.bearer != "" {
		headers = append(headers, [2]string{"Authorization", "Bearer " + o.bearer})
	}
	if o.js {
		if !request.HasHeader(headers, "Content-Type") {
			headers = append(headers, [2]string{"Content-Type", "application/json"})
		}
		if !request.HasHeader(headers, "Accept") {
			headers = append(headers, [2]string{"Accept", "application/json"})
		}
	}
	if body != "" && !request.HasHeader(headers, "Content-Type") {
		headers = append(headers, [2]string{"Content-Type", "application/x-www-form-urlencoded"}) // curl's default for -d
	}
	if !request.HasHeader(headers, "Host") {
		headers = append([][2]string{{"Host", pu.Host}}, headers...)
	}

	method := o.method
	if method == "" {
		switch {
		case o.head:
			method = "HEAD"
		case body != "":
			method = "POST"
		default:
			method = "GET"
		}
	}
	path := pu.RequestURI()
	return &Result{
		Method: method, Target: pu.Scheme + "://" + pu.Host, Path: path, Headers: headers, Body: body,
		Insecure: o.insecure, Follow: o.follow, Timeout: o.timeout,
		Raw:      request.Build(request.Message{Method: method, Path: path, Headers: headers, Body: body}),
		Warnings: o.warnings,
	}, nil
}
