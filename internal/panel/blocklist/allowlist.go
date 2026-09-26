package blocklist

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/audit"
	"github.com/billyriantono/dnsjos/internal/panel/db"
	"github.com/billyriantono/dnsjos/internal/panel/httpx"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// Allowlist (SPEC §7.5): names/IPs the nodes never block, enforced on the nodes within
// seconds and removed from the CDB by the next build.

const allowActive = "(a.expires_at IS NULL OR a.expires_at > now())"

const allowCols = `a.id, a.kind, a.value, a.reason, coalesce(u.email::text, ''), a.created_at, a.expires_at
	FROM allowlist a LEFT JOIN users u ON u.id = a.created_by`

func scanAllow(row pgx.Row) (api.AllowEntry, error) {
	var e api.AllowEntry
	err := row.Scan(&e.ID, &e.Kind, &e.Value, &e.Reason, &e.CreatedByEmail, &e.CreatedAt, &e.ExpiresAt)
	return e, err
}

// ActiveAllowlist returns the unexpired entries; Version hashes them (the agent ETag).
func ActiveAllowlist(ctx context.Context, q db.Querier) (api.Allowlist, error) {
	al := api.Allowlist{Domains: []string{}, IPs: []string{}}
	rows, _ := q.Query(ctx, `SELECT a.kind, a.value FROM allowlist a WHERE `+allowActive+
		` ORDER BY a.kind, a.value COLLATE "C"`)
	h := sha256.New()
	var kind, value string
	_, err := pgx.ForEachRow(rows, []any{&kind, &value}, func() error {
		fmt.Fprintf(h, "%s %s\n", kind, value)
		if kind == api.AllowDomain {
			al.Domains = append(al.Domains, value)
		} else {
			al.IPs = append(al.IPs, value)
		}
		return nil
	})
	al.Version = hex.EncodeToString(h.Sum(nil))[:16]
	return al, err
}

// parseAllowIP parses an address or CIDR into a masked prefix (IPv4-mapped → IPv4).
func parseAllowIP(v string) (netip.Prefix, error) {
	if !strings.Contains(v, "/") {
		a, err := netip.ParseAddr(v)
		if err != nil || a.Zone() != "" {
			return netip.Prefix{}, errors.New("bad address")
		}
		return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
	}
	p, err := netip.ParsePrefix(v)
	if err != nil {
		return p, err
	}
	bits := p.Bits()
	if p.Addr().Is4In6() {
		bits -= 96
	}
	if p = netip.PrefixFrom(p.Addr().Unmap(), bits).Masked(); !p.IsValid() {
		return p, errors.New("bad prefix")
	}
	return p, nil
}

// normalizeAllow returns the stored form of an entry, or a message saying why it is invalid.
func normalizeAllow(kind, v string) (string, string) {
	v = strings.TrimSpace(v)
	switch kind {
	case api.AllowDomain:
		n, ok := normalizeDomain(v)
		_, ipErr := netip.ParseAddr(n)
		switch {
		case !ok:
			return "", "value is not a valid domain name"
		case ipErr == nil:
			return "", "value is an IP address: use kind ip"
		case !strings.Contains(n, "."):
			return "", "a top-level domain cannot be allowlisted"
		}
		return n, ""
	case api.AllowIP:
		p, err := parseAllowIP(v)
		if err != nil {
			return "", "value is not an IP address or CIDR"
		}
		// Guards against typos such as /0 that would disable response-IP blocking.
		if p.Bits() < 8 || (p.Addr().Is6() && p.Bits() < 16) {
			return "", "prefix too broad (IPv4 needs /8 or longer, IPv6 /16 or longer)"
		}
		if p.IsSingleIP() {
			return p.Addr().String(), ""
		}
		return p.String(), ""
	}
	return "", "kind must be domain or ip"
}

func (s *Service) listAllow(w http.ResponseWriter, r *http.Request) {
	rows, _ := s.d.Pool.Query(r.Context(), "SELECT "+allowCols+" WHERE "+allowActive+" ORDER BY a.created_at DESC, a.value")
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (api.AllowEntry, error) { return scanAllow(row) })
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	if items == nil {
		items = []api.AllowEntry{}
	}
	httpx.WriteJSON(w, http.StatusOK, api.List[api.AllowEntry]{Items: items, Total: len(items)})
}

func (s *Service) createAllow(w http.ResponseWriter, r *http.Request) {
	var req api.AllowEntryCreate
	if err := httpx.ReadJSON(r, &req, httpx.MaxJSON); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	value, msg := normalizeAllow(req.Kind, req.Value)
	req.Reason = strings.TrimSpace(req.Reason)
	switch {
	case msg != "":
	case len(req.Reason) > 1000:
		msg = "reason must be at most 1000 bytes"
	case req.ExpiresAt != nil && !req.ExpiresAt.After(time.Now()):
		msg = "expires_at must be in the future"
	}
	if msg != "" {
		httpx.WriteError(w, http.StatusUnprocessableEntity, "invalid_entry", msg)
		return
	}
	var id string
	err := pgx.BeginFunc(r.Context(), s.d.Pool, func(tx pgx.Tx) error {
		// An expired row (not yet purged) is replaced; an active one is a duplicate.
		err := tx.QueryRow(r.Context(), `INSERT INTO allowlist (kind, value, reason, created_by, expires_at)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (kind, value) DO UPDATE SET reason = EXCLUDED.reason, created_by = EXCLUDED.created_by,
				created_at = now(), expires_at = EXCLUDED.expires_at
			WHERE allowlist.expires_at <= now()
			RETURNING id`, req.Kind, value, req.Reason, app.UserIDFrom(r.Context()), req.ExpiresAt).Scan(&id)
		if err != nil {
			return err
		}
		return audit.Record(r, tx, "allowlist.create", "allowlist", id,
			map[string]any{"kind": req.Kind, "value": value, "reason": req.Reason, "expires_at": req.ExpiresAt})
	})
	if db.IsNotFound(err) {
		httpx.WriteError(w, http.StatusConflict, "conflict", req.Kind+" "+value+" is already allowlisted")
		return
	} else if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	e, err := scanAllow(s.d.Pool.QueryRow(r.Context(), "SELECT "+allowCols+" WHERE a.id = $1", id))
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, e)
}

func (s *Service) deleteAllow(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := pgx.BeginFunc(r.Context(), s.d.Pool, func(tx pgx.Tx) error {
		var kind, value string
		if err := tx.QueryRow(r.Context(), "DELETE FROM allowlist WHERE id = $1 RETURNING kind, value", id).Scan(&kind, &value); err != nil {
			return err
		}
		return audit.Record(r, tx, "allowlist.delete", "allowlist", id, map[string]string{"kind": kind, "value": value})
	})
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// serveAllowlist is GET /agent/v1/allowlist with ETag = Version.
func (s *Service) serveAllowlist(w http.ResponseWriter, r *http.Request) {
	al, err := ActiveAllowlist(r.Context(), s.d.Pool)
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	etag := `"` + al.Version + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if httpx.ETagMatch(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, al)
}

// allowMatch sets res.Allowed/AllowEntry from the most specific active entry covering
// res.Name (an IP by containing prefix, a name by itself or a parent).
func allowMatch(ctx context.Context, q db.Querier, res *api.BlocklistLookup) error {
	var row pgx.Row
	if a, err := netip.ParseAddr(res.Name); err == nil {
		row = q.QueryRow(ctx, "SELECT "+allowCols+" WHERE a.kind = 'ip' AND "+allowActive+
			" AND CASE WHEN a.kind = 'ip' THEN a.value::inet >>= $1::inet END ORDER BY masklen(a.value::inet) DESC LIMIT 1", a.Unmap().String())
	} else if name, ok := normalizeDomain(res.Name); ok {
		var names []string
		for n := name; ; n = n[strings.IndexByte(n, '.')+1:] {
			names = append(names, n)
			if !strings.Contains(n, ".") {
				break
			}
		}
		row = q.QueryRow(ctx, "SELECT "+allowCols+" WHERE a.kind = 'domain' AND "+allowActive+
			" AND a.value = ANY($1) ORDER BY length(a.value) DESC LIMIT 1", names)
	} else {
		return nil
	}
	e, err := scanAllow(row)
	if db.IsNotFound(err) {
		return nil
	} else if err != nil {
		return err
	}
	res.Allowed, res.AllowEntry = true, &e
	return nil
}

// purgeAllow deletes expired entries (they are already ignored everywhere).
func (s *Service) purgeAllow(ctx context.Context) error {
	tag, err := s.d.Pool.Exec(ctx, "DELETE FROM allowlist WHERE expires_at <= now()")
	if n := tag.RowsAffected(); n > 0 {
		s.d.Log.Info("allowlist: expired entries purged", "deleted", n)
	}
	return err
}
