package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/audit"
	"github.com/billyriantono/dnsjos/internal/panel/httpx"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// Read-only API tokens (SPEC §10). Authentication itself lives in app.Router.Viewer.

const tokenCols = `SELECT t.id, t.name, t.prefix, coalesce(u.email::text, ''), t.created_at, t.last_used_at,
	t.expires_at, t.revoked_at IS NOT NULL FROM api_tokens t LEFT JOIN users u ON u.id = t.created_by`

func scanAPIToken(row pgx.Row) (api.APIToken, error) {
	var t api.APIToken
	err := row.Scan(&t.ID, &t.Name, &t.Prefix, &t.CreatedByEmail, &t.CreatedAt, &t.LastUsedAt, &t.ExpiresAt, &t.Revoked)
	return t, err
}

func (h *handlers) listAPITokens(w http.ResponseWriter, r *http.Request) {
	rows, _ := h.d.Pool.Query(r.Context(), tokenCols+" ORDER BY t.created_at DESC")
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (api.APIToken, error) { return scanAPIToken(row) })
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	if items == nil {
		items = []api.APIToken{}
	}
	httpx.WriteJSON(w, http.StatusOK, api.List[api.APIToken]{Items: items, Total: len(items)})
}

func (h *handlers) createAPIToken(w http.ResponseWriter, r *http.Request) {
	var req api.APITokenCreate
	if err := httpx.ReadJSON(r, &req, 4096); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 100 || req.ExpiresInDays < 0 || req.ExpiresInDays > 3650 {
		httpx.BadRequest(w, "name must be 1..100 bytes and expires_in_days 0..3650 (0 = never)")
		return
	}
	var expires *time.Time
	if req.ExpiresInDays > 0 {
		t := time.Now().AddDate(0, 0, req.ExpiresInDays)
		expires = &t
	}
	token := app.APITokenPrefix + app.NewToken()
	ctx := r.Context()
	var out api.APITokenCreated
	err := pgx.BeginFunc(ctx, h.d.Pool, func(tx pgx.Tx) error {
		var id string
		if err := tx.QueryRow(ctx, `INSERT INTO api_tokens (name, token_hash, prefix, created_by, expires_at)
			VALUES ($1, $2, $3, $4, $5) RETURNING id`, req.Name, app.HashToken(token), token[:8],
			app.UserIDFrom(ctx), expires).Scan(&id); err != nil {
			return err
		}
		var err error
		if out.APIToken, err = scanAPIToken(tx.QueryRow(ctx, tokenCols+" WHERE t.id = $1", id)); err != nil {
			return err
		}
		return audit.Record(r, tx, "api_token.create", "api_token", id,
			map[string]any{"name": req.Name, "prefix": out.Prefix, "expires_at": expires})
	})
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	out.Token = token
	httpx.WriteJSON(w, http.StatusCreated, out)
}

func (h *handlers) revokeAPIToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := pgx.BeginFunc(r.Context(), h.d.Pool, func(tx pgx.Tx) error {
		var name, prefix string
		if err := tx.QueryRow(r.Context(), `UPDATE api_tokens SET revoked_at = now()
			WHERE id = $1 AND revoked_at IS NULL RETURNING name, prefix`, id).Scan(&name, &prefix); err != nil {
			return err
		}
		return audit.Record(r, tx, "api_token.revoke", "api_token", id, map[string]string{"name": name, "prefix": prefix})
	})
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
