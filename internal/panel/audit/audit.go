// Package audit writes and lists the audit log. Every mutating admin action logs here.
package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/db"
	"github.com/billyriantono/dnsjos/internal/panel/httpx"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// Log inserts one audit row. Pass a pgx.Tx as q to make it part of the change.
func Log(ctx context.Context, q db.Querier, userID *string, action, targetType, targetID string, details any, ip string) error {
	if details == nil {
		details = struct{}{}
	}
	b, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `INSERT INTO audit_log (user_id, action, target_type, target_id, details, ip)
		VALUES ($1, $2, $3, $4, $5, $6)`, userID, action, targetType, targetID, b, ip)
	return err
}

// Record is Log with the user and client IP taken from the request.
func Record(r *http.Request, q db.Querier, action, targetType, targetID string, details any) error {
	return Log(r.Context(), q, app.UserIDFrom(r.Context()), action, targetType, targetID, details, httpx.ClientIP(r))
}

func Register(r *app.Router, d *app.Deps) {
	r.Admin("GET /api/v1/audit", func(w http.ResponseWriter, req *http.Request) {
		limit, _ := strconv.Atoi(req.URL.Query().Get("limit"))
		if limit <= 0 || limit > 500 {
			limit = 100
		}
		before, _ := strconv.ParseInt(req.URL.Query().Get("before"), 10, 64)
		rows, _ := d.Pool.Query(req.Context(), `
			SELECT a.id, a.at, a.user_id, coalesce(u.email::text, ''), a.action, a.target_type, a.target_id, a.details, a.ip
			FROM audit_log a LEFT JOIN users u ON u.id = a.user_id
			WHERE $1 = 0 OR a.id < $1
			ORDER BY a.id DESC LIMIT $2`, before, limit)
		items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (api.AuditEntry, error) {
			var e api.AuditEntry
			err := row.Scan(&e.ID, &e.At, &e.UserID, &e.UserEmail, &e.Action, &e.TargetType, &e.TargetID, &e.Details, &e.IP)
			return e, err
		})
		if err != nil {
			httpx.WriteDBError(w, req, err)
			return
		}
		var total int
		if err := d.Pool.QueryRow(req.Context(), "SELECT count(*) FROM audit_log").Scan(&total); err != nil {
			httpx.WriteDBError(w, req, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, api.List[api.AuditEntry]{Items: items, Total: total})
	})
}
