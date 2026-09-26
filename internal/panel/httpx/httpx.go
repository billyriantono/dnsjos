// Package httpx has the JSON helpers and middleware shared by every panel handler.
package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/billyriantono/dnsjos/internal/panel/db"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

const (
	MaxJSON = 1 << 20  // default request body limit
	MaxBody = 10 << 20 // hard cap for any request (the agent's blocked batches)
)

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func WriteError(w http.ResponseWriter, status int, code, msg string) {
	WriteJSON(w, status, api.ErrorBody{Error: api.ErrorDetail{Code: code, Message: msg}})
}

func BadRequest(w http.ResponseWriter, msg string) {
	WriteError(w, http.StatusBadRequest, "bad_request", msg)
}

func NotFound(w http.ResponseWriter) { WriteError(w, http.StatusNotFound, "not_found", "not found") }

// WriteDBError maps common Postgres errors to HTTP errors and logs the rest as 500.
func WriteDBError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case db.IsNotFound(err), db.IsInvalidInput(err):
		NotFound(w)
	case db.IsUniqueViolation(err):
		WriteError(w, http.StatusConflict, "conflict", "already exists")
	case db.IsForeignKeyViolation(err):
		WriteError(w, http.StatusConflict, "conflict", "referenced object does not exist or is in use")
	default:
		slog.ErrorContext(r.Context(), "request failed", "method", r.Method, "path", r.URL.Path, "err", err)
		WriteError(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

// ReadJSON decodes the request body into dst (unknown fields are ignored).
func ReadJSON(r *http.Request, dst any, maxBytes int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBytes))
	if err := dec.Decode(dst); err != nil {
		if mbe := (*http.MaxBytesError)(nil); errors.As(err, &mbe) {
			return fmt.Errorf("request body larger than %d bytes", maxBytes)
		}
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

// ETagMatch reports whether an If-None-Match header matches etag (weak comparison).
func ETagMatch(header, etag string) bool {
	for _, t := range strings.Split(header, ",") {
		t = strings.TrimPrefix(strings.TrimSpace(t), "W/")
		if t == etag || t == "*" {
			return true
		}
	}
	return false
}

// ClientIP returns the peer address; X-Forwarded-For is trusted only from a loopback
// peer (the local reverse proxy).
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if fwd := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(fwd) != nil {
				return fwd
			}
		}
	}
	return host
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Logging logs one line per request. Successful agent polls, health checks and static
// assets log at debug so the default level stays quiet.
func Logging(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		p := r.URL.Path
		level := slog.LevelInfo
		if sw.status < 400 && !strings.HasPrefix(p, "/api/") {
			level = slog.LevelDebug
		}
		log.Log(r.Context(), level, "http", "method", r.Method, "path", p, "status", sw.status,
			"bytes", sw.bytes, "dur_ms", time.Since(start).Milliseconds(), "ip", ClientIP(r))
	})
}

func Recover(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				log.Error("panic", "method", r.Method, "path", r.URL.Path, "panic", v, "stack", string(debug.Stack()))
				WriteError(w, http.StatusInternalServerError, "internal", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// CSRF requires "X-Requested-With: dnsjos" on mutating /api/ requests. Browsers cannot
// send custom headers cross-origin without a CORS preflight, which we never allow.
func CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if strings.HasPrefix(r.URL.Path, "/api/") && r.Header.Get("X-Requested-With") != "dnsjos" {
				WriteError(w, http.StatusForbidden, "csrf", "missing X-Requested-With header")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// BodyLimit caps every request body at n bytes.
func BodyLimit(n int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, n)
		}
		next.ServeHTTP(w, r)
	})
}

// CSVCell defuses spreadsheet formula injection: qnames come from arbitrary DNS clients.
func CSVCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
