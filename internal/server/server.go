// Package server exposes the curlp HTTP API and serves the embedded web UI.
package server

import (
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"curlp/internal/curl"
	"curlp/internal/request"
)

const maxSaved = 200

// Saved is a request in the sidebar list.
type Saved struct {
	ID       string `json:"id"`
	Method   string `json:"method"`
	Target   string `json:"target"`
	Path     string `json:"path"`
	Domain   string `json:"domain"`
	Raw      string `json:"raw"`
	Insecure bool   `json:"insecure"`
	Follow   bool   `json:"follow"`
	Timeout  int    `json:"timeout"`
	At       int64  `json:"at"`
}

// sendIn is the editor state sent by the UI (send, save and copy-as-cURL).
type sendIn struct {
	Target   string `json:"target"`
	Raw      string `json:"raw"`
	Insecure bool   `json:"insecure"`
	Follow   bool   `json:"follow"`
	Timeout  int    `json:"timeout"`
}

// Server holds the in-memory saved list (nothing is written to disk on purpose:
// requests often contain tokens and cookies).
type Server struct {
	port   string
	static fs.FS

	mu    sync.Mutex
	saved []Saved
}

func New(port string, static fs.FS) *Server { return &Server{port: port, static: static} }

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(s.static)))
	mux.HandleFunc("/api/send", s.handleSend)
	mux.HandleFunc("/api/tocurl", s.handleToCurl)
	mux.HandleFunc("/api/requests", s.handleSaved)
	mux.HandleFunc("/api/requests/import", s.handleImport)
	return s.guard(mux)
}

/* ---------------- helpers ---------------- */

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func badRequest(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 20<<20)).Decode(v); err != nil {
		badRequest(w, "Invalid JSON payload")
		return false
	}
	return true
}

// decodeMethod rejects every method except the expected one, then decodes the JSON body.
func decodeMethod(w http.ResponseWriter, r *http.Request, method string, v any) bool {
	if r.Method != method {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return decode(w, r, v)
}

// guard blocks DNS rebinding (Host check) and cross-site requests (Origin check + custom header).
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "127.0.0.1:"+s.port && r.Host != "localhost:"+s.port {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Method != http.MethodGet && r.Header.Get("X-Curlp") != "1" {
			http.Error(w, "missing header", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// normalize derives Method, Path, Domain and Target from the raw request text.
func normalize(sv *Saved) error {
	msg, err := request.Parse(sv.Raw)
	if err != nil {
		return err
	}
	full, err := request.ResolveURL(sv.Target, msg.Path, msg.Headers)
	if err != nil {
		return err
	}
	sv.Method, sv.Path = msg.Method, msg.Path
	if u, e := url.Parse(full); e == nil {
		sv.Domain = u.Host
		sv.Target = u.Scheme + "://" + u.Host
	}
	return nil
}

func (s *Server) add(sv *Saved) {
	sv.ID = strconv.FormatInt(time.Now().UnixNano(), 36)
	sv.At = time.Now().UnixMilli()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saved = append([]Saved{*sv}, s.saved...)
	if len(s.saved) > maxSaved {
		s.saved = s.saved[:maxSaved]
	}
}

/* ---------------- handlers ---------------- */

// POST /api/requests/import  {"command": "curl ..."}  -> parses the command and adds it to the list.
func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Command string `json:"command"`
	}
	if !decodeMethod(w, r, http.MethodPost, &in) {
		return
	}
	res, err := curl.Parse(in.Command)
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	sv := Saved{Target: res.Target, Raw: res.Raw, Insecure: res.Insecure, Follow: res.Follow, Timeout: res.Timeout}
	if err := normalize(&sv); err != nil {
		badRequest(w, err.Error())
		return
	}
	s.add(&sv)
	warnings := res.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": sv, "warnings": warnings})
}

// POST /api/tocurl  -> {"command": "curl ..."}
func (s *Server) handleToCurl(w http.ResponseWriter, r *http.Request) {
	var in sendIn
	if !decodeMethod(w, r, http.MethodPost, &in) {
		return
	}
	c, err := request.ToCurl(in.Target, in.Raw, in.Insecure, in.Follow)
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"command": c})
}

// GET list, POST create, PUT update (?id=), DELETE (?id= or ?all=1)
func (s *Server) handleSaved(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.saved == nil {
			writeJSON(w, http.StatusOK, []Saved{})
			return
		}
		writeJSON(w, http.StatusOK, s.saved)

	case http.MethodPost:
		var sv Saved
		if !decode(w, r, &sv) {
			return
		}
		if err := normalize(&sv); err != nil {
			badRequest(w, err.Error())
			return
		}
		s.add(&sv)
		writeJSON(w, http.StatusOK, sv)

	case http.MethodPut:
		var in Saved
		if !decode(w, r, &in) {
			return
		}
		if err := normalize(&in); err != nil {
			badRequest(w, err.Error())
			return
		}
		id := r.URL.Query().Get("id")
		s.mu.Lock()
		defer s.mu.Unlock()
		for i := range s.saved {
			if s.saved[i].ID == id {
				in.ID, in.At = id, time.Now().UnixMilli()
				s.saved[i] = in
				writeJSON(w, http.StatusOK, in)
				return
			}
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Saved request not found"})

	case http.MethodDelete:
		s.mu.Lock()
		defer s.mu.Unlock()
		if r.URL.Query().Get("all") == "1" {
			s.saved = nil
		} else {
			id := r.URL.Query().Get("id")
			for i := range s.saved {
				if s.saved[i].ID == id {
					s.saved = append(s.saved[:i], s.saved[i+1:]...)
					break
				}
			}
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
