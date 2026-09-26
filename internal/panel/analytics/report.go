package analytics

import (
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/billyriantono/dnsjos/internal/panel/db"
	"github.com/billyriantono/dnsjos/internal/panel/httpx"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

const maxRangeDays = 3660

type filter struct {
	from, to     time.Time
	nodeID, kind string
	limit        int
}

func parse(q url.Values, now time.Time) (f filter, err error) {
	f = filter{to: now.UTC().Truncate(24 * time.Hour), nodeID: q.Get("node_id"), kind: q.Get("kind"), limit: api.AnalyticsDefaultLimit}
	if s := q.Get("to"); s != "" {
		if f.to, err = time.Parse(time.DateOnly, s); err != nil {
			return f, errors.New("to: want YYYY-MM-DD")
		}
	}
	f.from = f.to.AddDate(0, 0, 1-api.AnalyticsDefaultDays)
	if s := q.Get("from"); s != "" {
		if f.from, err = time.Parse(time.DateOnly, s); err != nil {
			return f, errors.New("from: want YYYY-MM-DD")
		}
	}
	switch {
	case f.from.After(f.to):
		return f, errors.New("from must not be after to")
	case f.to.Sub(f.from) >= maxRangeDays*24*time.Hour:
		return f, fmt.Errorf("range: at most %d days", maxRangeDays)
	}
	if f.kind == "" {
		f.kind = api.AnalyticsQueried
	} else if !slices.Contains(api.AnalyticsKinds, f.kind) {
		return f, errors.New("kind: want one of " + strings.Join(api.AnalyticsKinds, ", "))
	}
	if s := q.Get("limit"); s != "" {
		if f.limit, err = strconv.Atoi(s); err != nil || f.limit < 1 || f.limit > api.AnalyticsMaxLimit {
			return f, fmt.Errorf("limit: want 1..%d", api.AnalyticsMaxLimit)
		}
	}
	return f, nil
}

func (s *svc) build(r *http.Request, f filter) (api.AnalyticsReport, error) {
	ctx := r.Context()
	rep := api.AnalyticsReport{From: f.from.Format(time.DateOnly), To: f.to.Format(time.DateOnly),
		ByQType: map[string]int64{}, ByRcode: map[string]int64{}, Top: []api.AnalyticsTopEntry{}}
	args := []any{rep.From, rep.To, f.nodeID}
	const node = " AND ($3 = '' OR node_id = nullif($3, '')::uuid)"

	perDay := map[string]int64{}
	rows, _ := s.d.Pool.Query(ctx, `SELECT day::text, total, by_qtype, by_rcode FROM analytics_daily_totals
		WHERE day BETWEEN $1::date AND $2::date`+node, args...)
	var day string
	var total int64
	var qt, rc map[string]int64
	_, err := pgx.ForEachRow(rows, []any{&day, &total, &qt, &rc}, func() error {
		perDay[day] += total
		rep.Total += total
		for k, v := range qt {
			rep.ByQType[k] += v
		}
		for k, v := range rc {
			rep.ByRcode[k] += v
		}
		qt, rc = nil, nil // Scan would merge into the previous row's maps
		return nil
	})
	if err != nil {
		return rep, err
	}
	for d := f.from; !d.After(f.to); d = d.AddDate(0, 0, 1) {
		k := d.Format(time.DateOnly)
		rep.ByDay = append(rep.ByDay, api.AnalyticsDay{Day: k, Total: perDay[k]})
	}

	base := rep.Total
	switch f.kind {
	case api.AnalyticsNXDomain:
		base = rep.ByRcode["NXDOMAIN"]
	case api.AnalyticsServfail:
		base = rep.ByRcode["SERVFAIL"]
	}
	rows, _ = s.d.Pool.Query(ctx, `
		SELECT t.name, sum(t.count)::bigint AS c, bool_or(t.error > 0 OR coalesce(d.sampled, false))
		FROM analytics_top_daily t
		LEFT JOIN analytics_daily_totals d ON d.day = t.day AND d.node_id = t.node_id
		WHERE t.day BETWEEN $1::date AND $2::date AND ($3 = '' OR t.node_id = nullif($3, '')::uuid) AND t.kind = $4
		GROUP BY t.name ORDER BY c DESC, t.name LIMIT $5`, append(args, f.kind, f.limit)...)
	var e api.AnalyticsTopEntry
	_, err = pgx.ForEachRow(rows, []any{&e.Name, &e.Count, &e.Approximate}, func() error {
		e.Rank = len(rep.Top) + 1
		if base > 0 {
			e.Share = min(1, float64(e.Count)/float64(base)) // Space-Saving can over-estimate
		}
		rep.Top = append(rep.Top, e)
		return nil
	})
	return rep, err
}

func (s *svc) handle(w http.ResponseWriter, r *http.Request) (f filter, rep api.AnalyticsReport, ok bool) {
	f, err := parse(r.URL.Query(), time.Now())
	if err != nil {
		httpx.BadRequest(w, err.Error())
		return f, rep, false
	}
	if rep, err = s.build(r, f); err != nil {
		if db.IsInvalidInput(err) {
			httpx.BadRequest(w, "invalid node_id")
		} else {
			httpx.WriteDBError(w, r, err)
		}
		return f, rep, false
	}
	return f, rep, true
}

func (s *svc) report(w http.ResponseWriter, r *http.Request) {
	if _, rep, ok := s.handle(w, r); ok {
		httpx.WriteJSON(w, http.StatusOK, rep)
	}
}

func (s *svc) csv(w http.ResponseWriter, r *http.Request) {
	f, rep, ok := s.handle(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="analytics-%s-%s_%s.csv"`, f.kind, rep.From, rep.To))
	cw := csv.NewWriter(w)
	cw.Write([]string{"rank", "name", "count", "share", "approximate"})
	for _, e := range rep.Top {
		cw.Write([]string{strconv.Itoa(e.Rank), httpx.CSVCell(e.Name), strconv.FormatInt(e.Count, 10),
			strconv.FormatFloat(e.Share, 'f', 6, 64), strconv.FormatBool(e.Approximate)})
	}
	cw.Flush()
}
