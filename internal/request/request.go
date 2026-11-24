// Package request parses, renders and converts raw HTTP/1.1 request text,
// the format Burp Repeater shows ("GET /path HTTP/1.1", headers, blank line, body).
package request

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var (
	// SchemeRe matches an absolute URL prefix such as "https://".
	SchemeRe  = regexp.MustCompile(`(?i)^[a-z][a-z0-9+.-]*://`)
	reqLineRe = regexp.MustCompile(`^(\S+)\s+(\S+)(?:\s+HTTP/[\d.]+)?\s*$`)
)

// Message is a parsed request: request line, ordered headers and body.
type Message struct {
	Method  string
	Path    string
	Headers [][2]string
	Body    string
}

// HasHeader reports whether a header exists (case-insensitive).
func HasHeader(h [][2]string, name string) bool {
	for _, x := range h {
		if strings.EqualFold(x[0], name) {
			return true
		}
	}
	return false
}

// HeaderValue returns the first value of a header, or "".
func HeaderValue(h [][2]string, name string) string {
	for _, x := range h {
		if strings.EqualFold(x[0], name) {
			return x[1]
		}
	}
	return ""
}

// Build renders a message the way the editor shows it. Lines are separated by \n.
func Build(m Message) string {
	var b strings.Builder
	b.WriteString(m.Method + " " + m.Path + " HTTP/1.1\n")
	for _, h := range m.Headers {
		b.WriteString(h[0] + ": " + h[1] + "\n")
	}
	b.WriteString("\n")
	b.WriteString(m.Body)
	return b.String()
}

// Parse reads raw request text (LF or CRLF line endings).
func Parse(raw string) (Message, error) {
	s := strings.TrimLeft(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	head, body := s, ""
	if i := strings.Index(s, "\n\n"); i >= 0 {
		head, body = s[:i], s[i+2:]
	}
	lines := strings.Split(head, "\n")
	m := reqLineRe.FindStringSubmatch(strings.TrimSpace(lines[0]))
	if m == nil {
		return Message{}, errors.New("invalid request line, expected: METHOD /path HTTP/1.1")
	}
	msg := Message{Method: strings.ToUpper(m[1]), Path: m[2], Body: body}
	for _, l := range lines[1:] {
		if k := strings.Index(l, ":"); k > 0 {
			msg.Headers = append(msg.Headers, [2]string{strings.TrimSpace(l[:k]), strings.TrimSpace(l[k+1:])})
		}
	}
	return msg, nil
}

// ResolveURL combines the Target field with the request-line path.
// An absolute URL in the path wins; an empty target falls back to the Host header.
func ResolveURL(target, path string, headers [][2]string) (string, error) {
	if SchemeRe.MatchString(path) {
		return path, nil
	}
	t := strings.TrimSpace(target)
	if t == "" {
		t = HeaderValue(headers, "Host")
	}
	if t == "" {
		return "", errors.New("set a target (for example https://example.com) or add a Host header")
	}
	if !SchemeRe.MatchString(t) {
		t = "https://" + t
	}
	pu, err := url.Parse(t)
	if err != nil || pu.Host == "" || (pu.Scheme != "http" && pu.Scheme != "https") {
		return "", fmt.Errorf("invalid target: %s", target)
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return pu.Scheme + "://" + pu.Host + path, nil
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// ToCurl converts raw request text and a target into a bash cURL command.
func ToCurl(target, raw string, insecure, follow bool) (string, error) {
	msg, err := Parse(raw)
	if err != nil {
		return "", err
	}
	full, err := ResolveURL(target, msg.Path, msg.Headers)
	if err != nil {
		return "", err
	}
	host := ""
	if pu, e := url.Parse(full); e == nil {
		host = pu.Host
	}
	var c strings.Builder
	c.WriteString("curl " + shQuote(full))
	if msg.Method != "GET" {
		c.WriteString(" -X " + msg.Method)
	}
	for _, h := range msg.Headers {
		if strings.EqualFold(h[0], "Host") && h[1] == host {
			continue
		}
		c.WriteString(" \\\n  -H " + shQuote(h[0]+": "+h[1]))
	}
	if msg.Body != "" {
		c.WriteString(" \\\n  --data-raw " + shQuote(msg.Body))
	}
	if insecure {
		c.WriteString(" -k")
	}
	if follow {
		c.WriteString(" -L")
	}
	return c.String(), nil
}
