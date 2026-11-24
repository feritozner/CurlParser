package server

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"curlp/internal/request"
)

const (
	maxBody  = 10 << 20  // response bodies are cut at 10 MB
	hexBytes = 256 << 10 // the hex view receives the first 256 KB
)

type sendOut struct {
	StatusCode int         `json:"status_code"`
	StatusText string      `json:"status_text"`
	Proto      string      `json:"proto"`
	Headers    [][2]string `json:"headers"`
	Body       string      `json:"body"`
	BodyB64    string      `json:"body_b64"`
	Binary     bool        `json:"binary"`
	Truncated  bool        `json:"truncated"`
	Size       int         `json:"size"`
	DurationMs int64       `json:"duration_ms"`
	FinalURL   string      `json:"final_url"`
	Error      string      `json:"error,omitempty"`
}

// POST /api/send  {target, raw, insecure, follow, timeout}
func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	var in sendIn
	if !decodeMethod(w, r, http.MethodPost, &in) {
		return
	}
	msg, err := request.Parse(in.Raw)
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	full, err := request.ResolveURL(in.Target, msg.Path, msg.Headers)
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	u, err := url.Parse(full)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		badRequest(w, "The URL must be an absolute http(s) address")
		return
	}

	body := msg.Body
	if strings.Contains(strings.ToLower(request.HeaderValue(msg.Headers, "Content-Type")), "multipart/") {
		body = strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n") // multipart needs CRLF; textareas only hold \n
	}
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(msg.Method, u.String(), rd)
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	for _, h := range msg.Headers {
		switch strings.ToLower(h[0]) {
		case "host":
			req.Host = h[1]
		case "content-length", "accept-encoding", "connection": // managed by Go (gzip is decoded automatically)
		default:
			req.Header[h[0]] = append(req.Header[h[0]], h[1]) // direct map write keeps the exact header casing
		}
	}

	timeout := time.Duration(in.Timeout) * time.Second
	if timeout <= 0 || timeout > 5*time.Minute {
		timeout = 30 * time.Second
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: in.Insecure}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Timeout: timeout, Transport: tr}
	if !in.Follow {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		writeJSON(w, http.StatusOK, sendOut{Error: "Request failed: " + err.Error(), DurationMs: time.Since(start).Milliseconds()})
		return
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	out := sendOut{
		StatusCode: resp.StatusCode, StatusText: http.StatusText(resp.StatusCode), Proto: resp.Proto,
		DurationMs: time.Since(start).Milliseconds(), FinalURL: resp.Request.URL.String(),
	}
	if len(raw) > maxBody {
		raw, out.Truncated = raw[:maxBody], true
	}
	out.Size = len(raw)
	out.BodyB64 = base64.StdEncoding.EncodeToString(raw[:min(len(raw), hexBytes)])
	switch {
	case bytes.IndexByte(raw[:min(len(raw), 8192)], 0) >= 0:
		out.Binary = true // NUL bytes: not text, use the Hex view
	case utf8.Valid(raw):
		out.Body = string(raw)
	default:
		out.Body = strings.ToValidUTF8(string(raw), "\uFFFD")
	}
	for k, vs := range resp.Header {
		for _, v := range vs {
			out.Headers = append(out.Headers, [2]string{k, v})
		}
	}
	sort.SliceStable(out.Headers, func(i, j int) bool {
		return strings.ToLower(out.Headers[i][0]) < strings.ToLower(out.Headers[j][0])
	})
	writeJSON(w, http.StatusOK, out)
}
