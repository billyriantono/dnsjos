package reports

import (
	"encoding/csv"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/billyriantono/dnsjos/internal/panel/httpx"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

const day = "2006-01-02"

// blockedFilter is a date range (inclusive, YYYY-MM-DD) plus an optional node.
type blockedFilter struct {
	from, to string
	nodeID   string
	limit    int
}

func parseBlocked(q url.Values, now time.Time, defLimit, maxLimit int) (f blockedFilter, err error) {
	to, from := now, now.AddDate(0, 0, -29)
	if s := q.Get("to"); s != "" {
		if to, err = time.Parse(day, s); err != nil {
			return f, errors.New("to: want YYYY-MM-DD")
		}
	}
	if s := q.Get("from"); s != "" {
		if from, err = time.Parse(day, s); err != nil {
			return f, errors.New("from: want YYYY-MM-DD")
		}
	} else if q.Get("to") != "" {
		from = to.AddDate(0, 0, -29)
	}
	f = blockedFilter{from: from.Format(day), to: to.Format(day), nodeID: q.Get("node_id"), limit: defLimit}
	if f.from > f.to {
		return f, errors.New("from must not be after to")
	}
	if n, _ := strconv.Atoi(q.Get("limit")); n > 0 {
		f.limit = min(n, maxLimit)
	}
	return f, nil
}

// where uses the blocked_daily primary key (day, node_id, …) for the range scan.
func (f blockedFilter) where() (string, []any) {
	args := []any{f.from, f.to}
	sql := " WHERE b.day BETWEEN $1::date AND $2::date"
	if f.nodeID != "" {
		args = append(args, f.nodeID)
		sql += " AND b.node_id = $3"
	}
	return sql, args
}

// query returns the SQL for one report section (a CSV kind).
func (f blockedFilter) query(kind string) (string, []any) {
	w, args := f.where()
	switch kind {
	case api.CSVSummary:
		return `SELECT b.node_id::text, n.name, sum(b.count)::bigint AS c
			FROM blocked_daily b JOIN nodes n ON n.id = b.node_id` + w + `
			GROUP BY b.node_id, n.name ORDER BY c DESC, n.name`, args
	case api.CSVMonthly:
		return `SELECT to_char(date_trunc('month', b.day), 'YYYY-MM') AS m, sum(b.count)::bigint
			FROM blocked_daily b` + w + ` GROUP BY m ORDER BY m`, args
	default:
		args = append(args, f.limit)
		return `SELECT b.qname, sum(b.count)::bigint AS c
			FROM blocked_daily b` + w + ` GROUP BY b.qname ORDER BY c DESC, b.qname LIMIT $` + strconv.Itoa(len(args)), args
	}
}

func (s *svc) rows(r *http.Request, f blockedFilter, kind string) (pgx.Rows, error) {
	sql, args := f.query(kind)
	return s.d.Pool.Query(r.Context(), sql, args...)
}

func (s *svc) blocked(w http.ResponseWriter, r *http.Request) {
	f, err := parseBlocked(r.URL.Query(), time.Now(), 100, 10000)
	if err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	rep := api.BlockedReport{ByNode: []api.BlockedByNode{}, ByMonth: []api.BlockedByMonth{}, TopDomains: []api.TopDomain{}}
	rows, _ := s.rows(r, f, api.CSVSummary)
	var bn api.BlockedByNode
	_, err = pgx.ForEachRow(rows, []any{&bn.NodeID, &bn.NodeName, &bn.Count}, func() error {
		rep.ByNode = append(rep.ByNode, bn)
		rep.Total += bn.Count
		return nil
	})
	if err == nil {
		rows, _ = s.rows(r, f, api.CSVMonthly)
		var bm api.BlockedByMonth
		_, err = pgx.ForEachRow(rows, []any{&bm.Month, &bm.Count}, func() error {
			rep.ByMonth = append(rep.ByMonth, bm)
			return nil
		})
	}
	if err == nil {
		rows, _ = s.rows(r, f, api.CSVTop)
		var td api.TopDomain
		_, err = pgx.ForEachRow(rows, []any{&td.QName, &td.Count}, func() error {
			rep.TopDomains = append(rep.TopDomains, td)
			return nil
		})
	}
	if err != nil {
		writeQueryErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rep)
}

// blockedCSV streams one report section as CSV straight from the DB rows.
func (s *svc) blockedCSV(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	if kind == "" {
		kind = api.CSVSummary
	}
	if !slices.Contains(api.CSVKinds, kind) {
		httpx.BadRequest(w, "kind: want one of "+strings.Join(api.CSVKinds, ", "))
		return
	}
	f, err := parseBlocked(r.URL.Query(), time.Now(), 1000, 1_000_000)
	if err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	header := map[string][]string{
		api.CSVSummary: {"node_id", "node_name", "count"},
		api.CSVMonthly: {"month", "count"},
		api.CSVTop:     {"qname", "count"},
	}[kind]
	rows, err := s.rows(r, f, kind)
	if err != nil {
		writeQueryErr(w, r, err)
		return
	}
	defer rows.Close()
	// Pull the first row before committing to a 200 so query errors still become JSON.
	more := rows.Next()
	if err := rows.Err(); err != nil {
		writeQueryErr(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="dnsjos-blocked-%s-%s-%s.csv"`, f.from, f.to, kind))
	cw := csv.NewWriter(w)
	cw.Write(header)
	for ; more; more = rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			break
		}
		rec := make([]string, len(vals))
		for i, v := range vals {
			rec[i] = cell(fmt.Sprint(v))
		}
		if cw.Write(rec) != nil {
			break
		}
	}
	cw.Flush()
	if err := rows.Err(); err != nil {
		slog.ErrorContext(r.Context(), "blocked csv aborted", "err", err)
	}
}

// cell defuses spreadsheet formula injection: qnames come from arbitrary DNS clients.
func cell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
