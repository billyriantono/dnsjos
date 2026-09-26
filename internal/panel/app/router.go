package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/billyriantono/dnsjos/internal/panel/db"
	"github.com/billyriantono/dnsjos/internal/panel/httpx"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

const (
	SessionCookie = "dnsjos_session"
	SessionTTL    = 12 * time.Hour
	// A session is extended at most once per this interval (saves a write per request).
	sessionRefresh = 10 * time.Minute
)

type ctxKey int

const (
	userKey ctxKey = iota
	nodeKey
)

// UserFrom returns the authenticated user (set by Viewer/Session/Admin routes).
func UserFrom(ctx context.Context) (api.User, bool) {
	u, ok := ctx.Value(userKey).(api.User)
	return u, ok
}

// UserIDFrom returns the authenticated user's id, or nil (handy for audit/created_by).
func UserIDFrom(ctx context.Context) *string {
	if u, ok := UserFrom(ctx); ok {
		return &u.ID
	}
	return nil
}

// NodeIDFrom returns the node id authenticated by an Agent route.
func NodeIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(nodeKey).(string)
	return id
}

// Router wraps http.ServeMux; every route declares its auth requirement.
type Router struct {
	mux *http.ServeMux
	d   *Deps
}

func NewRouter(d *Deps) *Router { return &Router{mux: http.NewServeMux(), d: d} }

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) { rt.mux.ServeHTTP(w, r) }

// Public registers a route without authentication.
func (rt *Router) Public(pattern string, h http.HandlerFunc) { rt.mux.Handle(pattern, h) }

// Viewer registers a read-only route open to any signed-in user. Pattern must be GET.
func (rt *Router) Viewer(pattern string, h http.HandlerFunc) {
	if !strings.HasPrefix(pattern, "GET ") {
		panic("app: Viewer routes must be GET-only: " + pattern)
	}
	rt.mux.Handle(pattern, rt.session("", h))
}

// Session registers a route for any signed-in user and any method (self-service
// endpoints such as logout and password change).
func (rt *Router) Session(pattern string, h http.HandlerFunc) {
	rt.mux.Handle(pattern, rt.session("", h))
}

// Admin registers a route that requires the admin role.
func (rt *Router) Admin(pattern string, h http.HandlerFunc) {
	rt.mux.Handle(pattern, rt.session(api.RoleAdmin, h))
}

// Agent registers a route authenticated by a node bearer token.
func (rt *Router) Agent(pattern string, h http.HandlerFunc) {
	rt.mux.Handle(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || tok == "" {
			httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "bearer token required")
			return
		}
		var id string
		err := rt.d.Pool.QueryRow(r.Context(),
			"SELECT id FROM nodes WHERE token_hash = $1 AND deleted_at IS NULL", HashToken(tok)).Scan(&id)
		if db.IsNotFound(err) {
			httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "unknown node token")
			return
		} else if err != nil {
			httpx.WriteDBError(w, r, err)
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), nodeKey, id)))
	}))
}

func (rt *Router) session(role string, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(SessionCookie)
		if err != nil || c.Value == "" {
			httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "sign in required")
			return
		}
		hash := HashToken(c.Value)
		var u api.User
		var expires time.Time
		err = rt.d.Pool.QueryRow(r.Context(), `
			SELECT u.id, u.email, u.name, u.role, u.disabled, u.created_at, u.last_login_at, s.expires_at
			FROM sessions s JOIN users u ON u.id = s.user_id
			WHERE s.id_hash = $1 AND s.expires_at > now() AND NOT u.disabled`, hash).
			Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.Disabled, &u.CreatedAt, &u.LastLoginAt, &expires)
		if db.IsNotFound(err) {
			ClearSessionCookie(w, rt.d.Cfg.SecureCookies)
			httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "session expired")
			return
		} else if err != nil {
			httpx.WriteDBError(w, r, err)
			return
		}
		if role != "" && u.Role != role {
			httpx.WriteError(w, http.StatusForbidden, "forbidden", "admin role required")
			return
		}
		if time.Until(expires) < SessionTTL-sessionRefresh {
			newExp := time.Now().Add(SessionTTL)
			if _, err := rt.d.Pool.Exec(r.Context(),
				"UPDATE sessions SET expires_at = $2 WHERE id_hash = $1", hash, newExp); err == nil {
				SetSessionCookie(w, c.Value, newExp, rt.d.Cfg.SecureCookies)
			}
		}
		h(w, r.WithContext(context.WithValue(r.Context(), userKey, u)))
	})
}

// NewToken returns 32 random bytes, base64url (no padding).
func NewToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashToken is how session, node and enrollment tokens are stored (sha256).
func HashToken(tok string) []byte {
	h := sha256.Sum256([]byte(tok))
	return h[:]
}

func SetSessionCookie(w http.ResponseWriter, token string, expires time.Time, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: token, Path: "/", Expires: expires,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	})
}

func ClearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	})
}
