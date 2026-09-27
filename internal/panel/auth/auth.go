// Package auth handles login/logout/sessions, users CRUD, API tokens and the first admin.
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/audit"
	"github.com/billyriantono/dnsjos/internal/panel/db"
	"github.com/billyriantono/dnsjos/internal/panel/httpx"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

const bcryptCost = 12

const userCols = "id, email, name, role, disabled, created_at, last_login_at"

func scanUser(row pgx.Row) (api.User, error) {
	var u api.User
	err := row.Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.Disabled, &u.CreatedAt, &u.LastLoginAt)
	return u, err
}

func hashPassword(pw string) (string, error) {
	if err := checkPassword(pw); err != nil {
		return "", err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	return string(h), err
}

func checkPassword(pw string) error {
	if len(pw) < 8 || len(pw) > 72 {
		return errors.New("password must be 8..72 bytes")
	}
	return nil
}

func weakPassword(w http.ResponseWriter, err error) {
	httpx.WriteError(w, http.StatusUnprocessableEntity, "weak_password", err.Error())
}

func checkEmail(email string) error {
	if a, err := mail.ParseAddress(email); err != nil || a.Address != email {
		return fmt.Errorf("%q is not a valid email address", email)
	}
	return nil
}

// CreateAdmin inserts an admin user (used by the CLI and the env bootstrap).
func CreateAdmin(ctx context.Context, pool *pgxpool.Pool, email, password, name string) (api.User, error) {
	email = strings.TrimSpace(email)
	if err := checkEmail(email); err != nil {
		return api.User{}, err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return api.User{}, err
	}
	return scanUser(pool.QueryRow(ctx, `INSERT INTO users (email, name, password_hash, role)
		VALUES ($1, $2, $3, 'admin') RETURNING `+userCols, email, name, hash))
}

// Bootstrap creates the env-configured admin when the users table is empty.
func Bootstrap(ctx context.Context, d *app.Deps) error {
	email, pw := d.Cfg.BootstrapAdminEmail, d.Cfg.BootstrapAdminPassword
	if email == "" || pw == "" {
		return nil
	}
	var exists bool
	if err := d.Pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM users)").Scan(&exists); err != nil || exists {
		return err
	}
	u, err := CreateAdmin(ctx, d.Pool, email, pw, "Administrator")
	if db.IsUniqueViolation(err) { // another panel won the race
		return nil
	} else if err != nil {
		return fmt.Errorf("bootstrap admin: %w", err)
	}
	d.Log.Info("bootstrap admin created", "email", u.Email)
	return audit.Log(ctx, d.Pool, nil, "user.bootstrap", "user", u.ID, map[string]string{"email": u.Email}, "")
}

// limiter is a fixed-window per-IP counter (10 login attempts per minute).
type limiter struct {
	mu sync.Mutex
	m  map[string]*window
}

type window struct {
	start time.Time
	n     int
}

func (l *limiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.m) > 10000 {
		for k, w := range l.m {
			if now.Sub(w.start) > time.Minute {
				delete(l.m, k)
			}
		}
	}
	w := l.m[ip]
	if w == nil || now.Sub(w.start) > time.Minute {
		w = &window{start: now}
		l.m[ip] = w
	}
	w.n++
	return w.n <= 10
}

var dummyHash = sync.OnceValue(func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte("dnsjos-timing-equaliser"), bcryptCost)
	return h
})

func Register(r *app.Router, d *app.Deps) {
	lim := &limiter{m: map[string]*window{}}
	h := &handlers{d: d}

	r.Public("POST /api/v1/auth/login", func(w http.ResponseWriter, req *http.Request) {
		ip := httpx.ClientIP(req)
		if !lim.allow(ip) {
			httpx.WriteError(w, http.StatusTooManyRequests, "rate_limited", "too many login attempts, try again in a minute")
			return
		}
		h.login(w, req, ip)
	})
	r.Public("POST /api/v1/auth/logout", h.logout)
	r.Viewer("GET /api/v1/auth/me", h.me)
	r.Session("PATCH /api/v1/auth/password", h.changePassword)

	r.Admin("GET /api/v1/users", h.listUsers)
	r.Admin("POST /api/v1/users", h.createUser)
	r.Admin("PATCH /api/v1/users/{id}", h.patchUser)
	r.Admin("DELETE /api/v1/users/{id}", h.deleteUser)

	r.Admin("GET /api/v1/api-tokens", h.listAPITokens)
	r.Admin("POST /api/v1/api-tokens", h.createAPIToken)
	r.Admin("DELETE /api/v1/api-tokens/{id}", h.revokeAPIToken)

	d.Jobs.Every("session-cleanup", time.Hour, func(ctx context.Context) error {
		_, err := d.Pool.Exec(ctx, "DELETE FROM sessions WHERE expires_at < now()")
		return err
	})
}

type handlers struct{ d *app.Deps }

func (h *handlers) login(w http.ResponseWriter, r *http.Request, ip string) {
	var req api.LoginRequest
	if err := httpx.ReadJSON(r, &req, 4096); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	ctx := r.Context()
	var u api.User
	var hash string
	err := h.d.Pool.QueryRow(ctx, "SELECT "+userCols+", password_hash FROM users WHERE email = $1",
		strings.TrimSpace(req.Email)).
		Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.Disabled, &u.CreatedAt, &u.LastLoginAt, &hash)
	if err != nil && !db.IsNotFound(err) {
		httpx.WriteDBError(w, r, err)
		return
	}
	if err != nil {
		bcrypt.CompareHashAndPassword(dummyHash(), []byte(req.Password)) // same cost as a real check
	}
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil || u.Disabled {
		audit.Log(ctx, h.d.Pool, nil, "auth.login_failed", "user", "", map[string]string{"email": req.Email}, ip)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_credentials", "wrong email or password")
		return
	}

	token := app.NewToken()
	expires := time.Now().Add(app.SessionTTL)
	ua := r.UserAgent()
	if len(ua) > 256 {
		ua = ua[:256]
	}
	err = pgx.BeginFunc(ctx, h.d.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO sessions (id_hash, user_id, expires_at, ip, user_agent)
			VALUES ($1, $2, $3, $4, $5)`, app.HashToken(token), u.ID, expires, ip, ua); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, "UPDATE users SET last_login_at = now() WHERE id = $1 RETURNING last_login_at",
			u.ID).Scan(&u.LastLoginAt); err != nil {
			return err
		}
		return audit.Log(ctx, tx, &u.ID, "auth.login", "user", u.ID, nil, ip)
	})
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	app.SetSessionCookie(w, token, expires, h.d.Cfg.SecureCookies)
	httpx.WriteJSON(w, http.StatusOK, api.Session{User: u, ExpiresAt: expires})
}

func (h *handlers) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(app.SessionCookie); err == nil && c.Value != "" {
		var uid string
		err := h.d.Pool.QueryRow(r.Context(), "DELETE FROM sessions WHERE id_hash = $1 RETURNING user_id",
			app.HashToken(c.Value)).Scan(&uid)
		if err == nil {
			audit.Log(r.Context(), h.d.Pool, &uid, "auth.logout", "user", uid, nil, httpx.ClientIP(r))
		}
	}
	app.ClearSessionCookie(w, h.d.Cfg.SecureCookies)
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) me(w http.ResponseWriter, r *http.Request) {
	u, _ := app.UserFrom(r.Context())
	var exp time.Time
	if c, err := r.Cookie(app.SessionCookie); err == nil {
		h.d.Pool.QueryRow(r.Context(), "SELECT expires_at FROM sessions WHERE id_hash = $1",
			app.HashToken(c.Value)).Scan(&exp)
	}
	httpx.WriteJSON(w, http.StatusOK, api.Session{User: u, ExpiresAt: exp})
}

func (h *handlers) changePassword(w http.ResponseWriter, r *http.Request) {
	u, _ := app.UserFrom(r.Context())
	var req api.PasswordChange
	if err := httpx.ReadJSON(r, &req, 4096); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	ctx := r.Context()
	var cur string
	if err := h.d.Pool.QueryRow(ctx, "SELECT password_hash FROM users WHERE id = $1", u.ID).Scan(&cur); err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(cur), []byte(req.Current)) != nil {
		httpx.WriteError(w, http.StatusForbidden, "invalid_credentials", "current password is wrong")
		return
	}
	hash, err := hashPassword(req.New)
	if err != nil {
		weakPassword(w, err)
		return
	}
	c, _ := r.Cookie(app.SessionCookie)
	err = pgx.BeginFunc(ctx, h.d.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "UPDATE users SET password_hash = $2 WHERE id = $1", u.ID, hash); err != nil {
			return err
		}
		// Sign out every other session of this user.
		if _, err := tx.Exec(ctx, "DELETE FROM sessions WHERE user_id = $1 AND id_hash <> $2",
			u.ID, app.HashToken(c.Value)); err != nil {
			return err
		}
		return audit.Record(r, tx, "auth.password_change", "user", u.ID, nil)
	})
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) listUsers(w http.ResponseWriter, r *http.Request) {
	rows, _ := h.d.Pool.Query(r.Context(), "SELECT "+userCols+" FROM users ORDER BY email")
	users, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (api.User, error) { return scanUser(row) })
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, api.List[api.User]{Items: users, Total: len(users)})
}

func (h *handlers) createUser(w http.ResponseWriter, r *http.Request) {
	var req api.UserCreate
	if err := httpx.ReadJSON(r, &req, 4096); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Role == "" {
		req.Role = api.RoleViewer
	}
	if err := checkEmail(req.Email); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	if req.Role != api.RoleAdmin && req.Role != api.RoleViewer {
		httpx.BadRequest(w, "role must be admin or viewer")
		return
	}
	hash, err := hashPassword(req.Password)
	if err != nil {
		weakPassword(w, err)
		return
	}
	ctx := r.Context()
	var u api.User
	err = pgx.BeginFunc(ctx, h.d.Pool, func(tx pgx.Tx) error {
		var err error
		u, err = scanUser(tx.QueryRow(ctx, `INSERT INTO users (email, name, password_hash, role)
			VALUES ($1, $2, $3, $4) RETURNING `+userCols, req.Email, req.Name, hash, req.Role))
		if err != nil {
			return err
		}
		return audit.Record(r, tx, "user.create", "user", u.ID, map[string]string{"email": u.Email, "role": u.Role})
	})
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, u)
}

var errLastAdmin = errors.New("cannot remove the last admin")

// lockLastAdmin fails when id is the only enabled admin. It locks the admin rows so two
// concurrent demotions cannot both pass.
func lockLastAdmin(ctx context.Context, tx pgx.Tx, id string) error {
	rows, _ := tx.Query(ctx, "SELECT id FROM users WHERE role = 'admin' AND NOT disabled FOR UPDATE")
	admins, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, a := range admins {
		if a != id {
			return nil
		}
	}
	if len(admins) == 0 { // target is not an enabled admin
		return nil
	}
	return errLastAdmin
}

func (h *handlers) patchUser(w http.ResponseWriter, r *http.Request) {
	me, _ := app.UserFrom(r.Context())
	id := r.PathValue("id")
	var req api.UserPatch
	if err := httpx.ReadJSON(r, &req, 4096); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	if req.Role != nil && *req.Role != api.RoleAdmin && *req.Role != api.RoleViewer {
		httpx.BadRequest(w, "role must be admin or viewer")
		return
	}
	if id == me.ID && req.Disabled != nil && *req.Disabled {
		httpx.BadRequest(w, "you cannot disable yourself")
		return
	}
	var hash *string
	if req.Password != nil {
		s, err := hashPassword(*req.Password)
		if err != nil {
			weakPassword(w, err)
			return
		}
		hash = &s
	}
	ctx := r.Context()
	var u api.User
	err := pgx.BeginFunc(ctx, h.d.Pool, func(tx pgx.Tx) error {
		demote := (req.Role != nil && *req.Role != api.RoleAdmin) || (req.Disabled != nil && *req.Disabled)
		if demote {
			if err := lockLastAdmin(ctx, tx, id); err != nil {
				return err
			}
		}
		var err error
		u, err = scanUser(tx.QueryRow(ctx, `UPDATE users SET
				name = coalesce($2, name), role = coalesce($3, role),
				disabled = coalesce($4, disabled), password_hash = coalesce($5, password_hash)
			WHERE id = $1 RETURNING `+userCols, id, req.Name, req.Role, req.Disabled, hash))
		if err != nil {
			return err
		}
		if u.Disabled || hash != nil {
			if _, err := tx.Exec(ctx, "DELETE FROM sessions WHERE user_id = $1", id); err != nil {
				return err
			}
		}
		return audit.Record(r, tx, "user.update", "user", id, map[string]any{
			"name": req.Name, "role": req.Role, "disabled": req.Disabled, "password_changed": hash != nil})
	})
	if errors.Is(err, errLastAdmin) {
		httpx.WriteError(w, http.StatusConflict, "last_admin", err.Error())
		return
	} else if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

func (h *handlers) deleteUser(w http.ResponseWriter, r *http.Request) {
	me, _ := app.UserFrom(r.Context())
	id := r.PathValue("id")
	if id == me.ID {
		httpx.BadRequest(w, "you cannot delete yourself")
		return
	}
	ctx := r.Context()
	err := pgx.BeginFunc(ctx, h.d.Pool, func(tx pgx.Tx) error {
		if err := lockLastAdmin(ctx, tx, id); err != nil {
			return err
		}
		var email string
		if err := tx.QueryRow(ctx, "DELETE FROM users WHERE id = $1 RETURNING email", id).Scan(&email); err != nil {
			return err
		}
		return audit.Record(r, tx, "user.delete", "user", id, map[string]string{"email": email})
	})
	if errors.Is(err, errLastAdmin) {
		httpx.WriteError(w, http.StatusConflict, "last_admin", err.Error())
		return
	} else if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
