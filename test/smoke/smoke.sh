#!/usr/bin/env bash
# Route smoke test: runs the real panel against a fresh database and hits every route of
# SPEC §8 and §10 with valid and invalid input. Fails on any 5xx or unexpected status.
#
#   test/smoke/smoke.sh                        # builds ./cmd/dnsjos
#   PANEL_BIN=bin/dnsjos EXPECT_AGENT=1 test/smoke/smoke.sh   # a `make release` build
#
# Env: PGHOST/PGPORT/PGUSER as for createdb (default 127.0.0.1:5432 $USER), SMOKE_ADDR.
set -euo pipefail
cd "$(dirname "$0")/../.."

export PGHOST=${PGHOST:-127.0.0.1} PGPORT=${PGPORT:-5432} PGUSER=${PGUSER:-$USER}
ADDR=${SMOKE_ADDR:-127.0.0.1:18090}
B=http://$ADDR
DB=dnsjos_smoke_$$
TMP=$(mktemp -d)
PID=

cleanup() {
	[ -n "$PID" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
	dropdb --if-exists "$DB" 2>/dev/null || true
	rm -rf "$TMP"
}
trap cleanup EXIT

BIN=${PANEL_BIN:-$TMP/dnsjos}
[ -n "${PANEL_BIN:-}" ] || ${GO:-go} build -o "$BIN" ./cmd/dnsjos
createdb "$DB"

DNSJOS_LISTEN=$ADDR DNSJOS_DATABASE_URL="postgres://$PGUSER@$PGHOST:$PGPORT/$DB?sslmode=disable" \
	DNSJOS_DATA_DIR=$TMP/data DNSJOS_PUBLIC_URL=$B DNSJOS_LOG_LEVEL=warn \
	DNSJOS_BOOTSTRAP_ADMIN_EMAIL=admin@example.com DNSJOS_BOOTSTRAP_ADMIN_PASSWORD=admin-pass-1 \
	"$BIN" serve 2>"$TMP/panel.log" &
PID=$!
for _ in $(seq 100); do curl -fs "$B/healthz" >/dev/null 2>&1 && break; sleep 0.2; done
curl -fs "$B/healthz" >/dev/null || { cat "$TMP/panel.log"; echo "panel did not start"; exit 1; }

FAILS=0 N=0
# req WANT AUTH METHOD PATH [BODY] [curl args…] — AUTH: admin | viewer | none | <node token>.
# WANT "*" accepts any non-5xx. The response body is left in $TMP/body.
req() {
	local want=$1 auth=$2 method=$3 path=$4 body=${5:-} args=()
	shift $(($# < 5 ? $# : 5))
	case $auth in
	admin | viewer) args+=(-b "$TMP/$auth.jar" -c "$TMP/$auth.jar") ;;
	none) ;;
	*) args+=(-H "Authorization: Bearer $auth") ;;
	esac
	[ -n "$body" ] && args+=(-H 'Content-Type: application/json' --data-raw "$body")
	local code
	code=$(curl -s -o "$TMP/body" -w '%{http_code}' -X "$method" -H 'X-Requested-With: dnsjos' \
		${args[@]+"${args[@]}"} "$@" "$B$path")
	N=$((N + 1))
	if [[ $code == 5* || ($want != "*" && $code != "$want") ]]; then
		FAILS=$((FAILS + 1))
		echo "FAIL $method $path ($auth): got $code want $want: $(head -c 300 "$TMP/body")"
	fi
}
j() { jq -r "$1" "$TMP/body"; }
Z=00000000-0000-0000-0000-000000000000

# ── health, SPA, installer ──
req 200 none GET /healthz
req 200 none GET /readyz
req 200 none GET /
req 200 none GET /nodes/some/client/route
req 404 none GET /api/v1/nope
req 404 none GET /agent/v1/nope
req 200 none GET /install.sh
req 404 none GET /dl/agent/linux/mips
if [ -n "${EXPECT_AGENT:-}" ]; then
	req 200 none GET /dl/agent/linux/amd64
	cp "$TMP/body" "$TMP/agent"
	req 200 none GET /dl/agent/linux/amd64.sha256
	[ "$(tr -d '[:space:]' <"$TMP/body")" = "$(shasum -a 256 "$TMP/agent" | cut -d' ' -f1)" ] ||
		{ FAILS=$((FAILS + 1)); echo "FAIL agent sha256 mismatch"; }
	req 200 none GET /dl/agent/linux/arm64.sha256
else
	req 404 none GET /dl/agent/linux/amd64
fi

# ── auth ──
req 401 none GET /api/v1/auth/me
req 400 none POST /api/v1/auth/login '{bad'
req 401 none POST /api/v1/auth/login '{"email":"admin@example.com","password":"wrong-pass"}'
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/api/v1/auth/logout")" = 403 ] ||
	{ FAILS=$((FAILS + 1)); echo "FAIL CSRF guard: mutating request without X-Requested-With accepted"; }
req 200 admin POST /api/v1/auth/login '{"email":"admin@example.com","password":"admin-pass-1"}'
req 200 admin GET /api/v1/auth/me
req 403 admin PATCH /api/v1/auth/password '{"current":"wrong-pass","new":"admin-pass-2"}'
req 422 admin PATCH /api/v1/auth/password '{"current":"admin-pass-1","new":"short"}'
req 400 admin PATCH /api/v1/auth/password '[]'
req 204 admin PATCH /api/v1/auth/password '{"current":"admin-pass-1","new":"admin-pass-2"}'

# ── users & audit ──
req 200 admin GET /api/v1/users
req 422 admin POST /api/v1/users '{"email":"v@example.com","password":"short","role":"viewer"}'
req 400 admin POST /api/v1/users '{"email":"not-an-email","password":"viewer-pass","role":"viewer"}'
req 400 admin POST /api/v1/users '{"email":"v@example.com","password":"viewer-pass","role":"root"}'
req 201 admin POST /api/v1/users '{"email":"v@example.com","password":"viewer-pass","role":"viewer"}'
VIEWER=$(j .id)
req 409 admin POST /api/v1/users '{"email":"v@example.com","password":"viewer-pass","role":"viewer"}'
req 200 admin PATCH "/api/v1/users/$VIEWER" '{"name":"Viewer"}'
req 422 admin PATCH "/api/v1/users/$VIEWER" '{"password":"1234567"}'
req 404 admin PATCH /api/v1/users/not-a-uuid '{"name":"x"}'
req 404 admin PATCH "/api/v1/users/$Z" '{"name":"x"}'
req 200 viewer POST /api/v1/auth/login '{"email":"v@example.com","password":"viewer-pass"}'
req 403 viewer GET /api/v1/users
req 403 viewer GET /api/v1/audit
req 200 admin GET /api/v1/audit
req 200 admin GET '/api/v1/audit?limit=5&before=999999'
req '*' admin GET '/api/v1/audit?limit=abc&before=xyz'

# ── read-only API tokens ──
req 403 viewer GET /api/v1/api-tokens
req 400 admin POST /api/v1/api-tokens '{"name":" "}'
req 400 admin POST /api/v1/api-tokens '{"name":"x","expires_in_days":-1}'
req 201 admin POST /api/v1/api-tokens '{"name":"grafana","expires_in_days":30}'
APITOK=$(j .token) APITOK_ID=$(j .id)
[[ $APITOK == djt_* ]] || { FAILS=$((FAILS + 1)); echo "FAIL api token format"; }
req 200 "$APITOK" GET /api/v1/reports/blocked
req 200 "$APITOK" GET /api/v1/overview
req 401 "$APITOK" GET /api/v1/users
req 401 "$APITOK" GET /api/v1/api-tokens
req 401 "$APITOK" PUT /api/v1/settings '{"metrics_retention_days":10}'
req 401 "$APITOK" POST /api/v1/blocklist/builds
req 401 "$APITOK" GET /agent/v1/config
req 401 djt_not-a-token GET /api/v1/overview
req 200 admin GET /api/v1/api-tokens
grep -q "$APITOK" "$TMP/body" && { FAILS=$((FAILS + 1)); echo "FAIL api token list leaks the secret"; }
[ "$(j '.items[0].last_used_at')" != null ] || { FAILS=$((FAILS + 1)); echo "FAIL api token last_used_at not set"; }
req 204 admin DELETE "/api/v1/api-tokens/$APITOK_ID"
req 404 admin DELETE "/api/v1/api-tokens/$APITOK_ID"
req 404 admin DELETE /api/v1/api-tokens/not-a-uuid
req 401 "$APITOK" GET /api/v1/overview

# ── settings ──
req 200 viewer GET /api/v1/settings
req 403 viewer PUT /api/v1/settings '{"metrics_retention_days":10}'
req 200 admin PUT /api/v1/settings '{"metrics_retention_days":30}'
req 400 admin PUT /api/v1/settings '{"agent_poll_interval_s":1}'
req 200 admin PUT /api/v1/settings '{"analytics_retention_days":400}'
[ "$(j .analytics_retention_days)" = 400 ] || { FAILS=$((FAILS + 1)); echo "FAIL analytics retention setting: $(j .analytics_retention_days)"; }
req 400 admin PUT /api/v1/settings '{"analytics_retention_days":0}'
req 400 admin PUT /api/v1/settings '{"public_url":"javascript:alert(1)"}'
req 400 admin PUT /api/v1/settings 'nope'
req 400 admin PUT /api/v1/settings '{"blocklist_download_segments":0}'
req 400 admin PUT /api/v1/settings '{"blocklist_download_segments":17}'
req 200 admin PUT /api/v1/settings '{"blocklist_download_segments":4}'
[ "$(j .blocklist_download_segments)" = 4 ] || { FAILS=$((FAILS + 1)); echo "FAIL download segments setting: $(cat "$TMP/body")"; }

# ── overview & metrics ──
req 200 viewer GET /api/v1/overview
req 200 viewer GET /api/v1/overview/metrics
req 200 viewer GET '/api/v1/overview/metrics?step=5m'
req 400 viewer GET '/api/v1/overview/metrics?from=yesterday'
req 400 viewer GET '/api/v1/overview/metrics?step=10s'
req 400 viewer GET '/api/v1/overview/metrics?from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z'

# ── profiles & versions ──
req 200 viewer GET /api/v1/profiles
DEFAULT=$(j '.items[] | select(.name=="default") | .id')
req 403 viewer POST /api/v1/profiles '{"name":"x"}'
req 400 admin POST /api/v1/profiles '{}'
req 400 admin POST /api/v1/profiles '{"name":"x","copy_from":"not-a-uuid"}'
req 400 admin POST /api/v1/profiles "{\"name\":\"x\",\"copy_from\":\"$Z\"}"
req 201 admin POST /api/v1/profiles '{"name":"edge","description":"edge nodes"}'
PROF=$(j .id)
[ "$(j .published_version)" = 1 ] || { FAILS=$((FAILS + 1)); echo "FAIL new profile has no published v1"; }
req 201 admin POST /api/v1/profiles "{\"name\":\"edge-copy\",\"copy_from\":\"$DEFAULT\"}"
COPY=$(j .id)
req 409 admin POST /api/v1/profiles '{"name":"edge"}'
req 200 viewer GET "/api/v1/profiles/$PROF"
req 404 viewer GET /api/v1/profiles/not-a-uuid
req 404 viewer GET "/api/v1/profiles/$Z"
req 200 admin PATCH "/api/v1/profiles/$PROF" '{"description":"edited"}'
req 400 admin PATCH "/api/v1/profiles/$PROF" '{"name":""}'
req 404 admin PATCH "/api/v1/profiles/$Z" '{"description":"x"}'
req 200 viewer GET "/api/v1/profiles/$PROF/versions"
req 404 viewer GET "/api/v1/profiles/$Z/versions"
req 200 viewer GET "/api/v1/profiles/$PROF/versions/1"
SPEC=$(jq -c .spec "$TMP/body")
req 404 viewer GET "/api/v1/profiles/$PROF/versions/x"
req 404 viewer GET "/api/v1/profiles/$PROF/versions/99"
V2=$(jq -c '.upstreams.servers[0].weight = 50' <<<"$SPEC")
req 201 admin POST "/api/v1/profiles/$PROF/versions" "{\"spec\":$V2,\"comment\":\"w50\"}"
req 422 admin POST "/api/v1/profiles/$PROF/versions" '{"spec":{}}'
req 400 admin POST "/api/v1/profiles/$PROF/versions" '{"spec":"x"}'
req 404 admin POST "/api/v1/profiles/$Z/versions" "{\"spec\":$SPEC}"
req 404 admin POST "/api/v1/profiles/not-a-uuid/versions" "{\"spec\":$SPEC}"
req 200 admin POST "/api/v1/profiles/$PROF/versions/2/publish"
req 404 admin POST "/api/v1/profiles/$PROF/versions/99/publish"
req 404 admin POST "/api/v1/profiles/$PROF/versions/x/publish"
req 200 viewer GET "/api/v1/profiles/$PROF/versions/1/diff/2"
[ "$(j '.changes | length')" = 1 ] || { FAILS=$((FAILS + 1)); echo "FAIL diff changes: $(j .changes)"; }
req 404 viewer GET "/api/v1/profiles/$PROF/versions/1/diff/99"
req 404 viewer GET "/api/v1/profiles/$PROF/versions/a/diff/b"
req 200 viewer POST "/api/v1/profiles/$PROF/preview" "{\"spec\":$SPEC}"
req 422 viewer POST "/api/v1/profiles/$PROF/preview" '{"spec":{}}'
req 400 viewer POST "/api/v1/profiles/$PROF/preview" 'garbage'
req 404 viewer POST "/api/v1/profiles/$Z/preview" "{\"spec\":$SPEC}"

# ── enrollment & agent protocol ──
req 200 viewer GET /api/v1/enrollment-tokens
req 403 viewer POST /api/v1/enrollment-tokens '{"node_name":"ns1"}'
req 400 admin POST /api/v1/enrollment-tokens '{"node_name":"bad name"}'
req 400 admin POST /api/v1/enrollment-tokens '{"node_name":"ns1","ttl_hours":9999}'
req 400 admin POST /api/v1/enrollment-tokens '{"node_name":"ns1","profile_id":"not-a-uuid"}'
req 400 admin POST /api/v1/enrollment-tokens "{\"node_name\":\"ns1\",\"profile_id\":\"$Z\"}"
req 201 admin POST /api/v1/enrollment-tokens "{\"node_name\":\"ns1\",\"profile_id\":\"$PROF\",\"labels\":{\"site\":\"jkt\"}}"
TOK=$(j .token) TOKID=$(j .id)
req 201 admin POST /api/v1/enrollment-tokens '{"node_name":"old1"}'
ADOPT_TOK=$(j .token)
req 400 none POST /agent/v1/enroll '{}'
req 400 none POST /agent/v1/enroll 'garbage'
req 401 none POST /agent/v1/enroll '{"token":"nope"}'
req 200 none POST /agent/v1/enroll "{\"token\":\"$TOK\",\"hostname\":\"ns1.example\",\"os\":\"debian 12\",\"arch\":\"amd64\"}"
NODE=$(j .node_id) NTOK=$(j .node_token)
[ "$(j .name)" = ns1 ] || { FAILS=$((FAILS + 1)); echo "FAIL enroll name: $(j .name)"; }
req 401 none POST /agent/v1/enroll "{\"token\":\"$TOK\"}"
req 422 none POST /agent/v1/enroll "{\"token\":\"$ADOPT_TOK\",\"adopt\":true,\"adopt_overrides\":{\"webserver\":{\"listen\":\"bogus\"}}}"
req 422 none POST /agent/v1/enroll "{\"token\":\"$ADOPT_TOK\",\"adopt\":true,\"adopt_overrides\":[1]}"
req 200 none POST /agent/v1/enroll "{\"token\":\"$ADOPT_TOK\",\"hostname\":\"old1\",\"adopt\":true,\"adopt_overrides\":{\"webserver\":{\"listen\":\"0.0.0.0:8083\"}}}"
ADOPTED=$(j .node_id) ATOK=$(j .node_token)

req 401 none GET /agent/v1/config
req 401 nope-token GET /agent/v1/config
req 200 "$NTOK" GET /agent/v1/config
ETAG=$(jq -r .version "$TMP/body")
[ "$(j '.allowlist_version | length')" = 16 ] || { FAILS=$((FAILS + 1)); echo "FAIL config allowlist_version: $(j .allowlist_version)"; }
req 304 "$NTOK" GET /agent/v1/config '' -H "If-None-Match: \"$ETAG\""
req 409 "$ATOK" GET /agent/v1/config
req 404 "$NTOK" GET /agent/v1/blocklist
req 400 "$NTOK" POST /agent/v1/heartbeat 'garbage'
HB='{"time":"2026-09-27T00:00:00Z","agent_version":"1","dnsdist_running":true,"applied_config_version":1,
 "blocklist_sha256":"seeded","counters":{"queries":10},"backends":[{"address":"1.1.1.1:53","state":"up"}],
 "dynblocks":[{"client":"192.0.2.1/32","reason":"rate","stage":"blocked","blocks":3}]}'
req 200 "$NTOK" POST /agent/v1/heartbeat "$HB"
req 200 "$NTOK" POST /agent/v1/heartbeat "${HB/00:00:00Z/00:00:10Z}"
[ "$(j '.allowlist_version | length')" = 16 ] || { FAILS=$((FAILS + 1)); echo "FAIL heartbeat allowlist_version: $(cat "$TMP/body")"; }
req 200 "$ATOK" POST /agent/v1/heartbeat "$HB"
req 200 "$ATOK" GET /agent/v1/config
req 204 "$NTOK" POST /agent/v1/blocked '{"items":[{"day":"2026-09-26","qname":"bad.example","qtype":"A","count":3}]}'
req 204 "$NTOK" POST /agent/v1/blocked '{"items":[{"day":"nope","qname":"","qtype":"","count":-1}]}'
req 400 "$NTOK" POST /agent/v1/blocked 'garbage'
req 204 "$NTOK" POST /agent/v1/cgk '{"measured_at":"2026-09-27T00:00:00Z","ok":true,"aliases":["104.16.0.1"],"rewrite_ranges":["104.20.0.0/16"],"pools":[{"net":"104.20.0.0/16","colos":["CGK"]}]}'
req 400 "$NTOK" POST /agent/v1/cgk 'garbage'
TODAY=$(date -u +%F)
AB="{\"day\":\"$TODAY\",\"total\":10,\"sample_rate\":1,\"by_qtype\":{\"A\":10},\"by_rcode\":{\"NOERROR\":8,\"NXDOMAIN\":2},
 \"tops\":{\"queried\":[{\"name\":\"www.example.com\",\"count\":6,\"error\":0}],\"nxdomain\":[{\"name\":\"nope.example\",\"count\":2,\"error\":0}]}}"
req 204 "$NTOK" POST /agent/v1/analytics "$AB"
req 204 "$NTOK" POST /agent/v1/analytics "$AB"
req 422 "$NTOK" POST /agent/v1/analytics "{\"day\":\"$TODAY\",\"sample_rate\":1,\"tops\":{\"clients\":[]}}"
req 422 "$NTOK" POST /agent/v1/analytics '{"day":"nope","sample_rate":0}'
req 400 "$NTOK" POST /agent/v1/analytics 'garbage'
req 401 none POST /agent/v1/analytics "$AB"

# ── nodes ──
req 200 viewer GET /api/v1/nodes
req 200 viewer GET "/api/v1/nodes/$NODE"
req 404 viewer GET /api/v1/nodes/not-a-uuid
req 404 viewer GET "/api/v1/nodes/$Z"
req 200 viewer GET "/api/v1/nodes/$NODE/live"
req 404 viewer GET "/api/v1/nodes/$Z/live"
req 200 viewer GET "/api/v1/nodes/$NODE/metrics"
req 400 viewer GET "/api/v1/nodes/$NODE/metrics?step=abc"
req 404 viewer GET "/api/v1/nodes/$Z/metrics"
req 404 viewer GET /api/v1/nodes/not-a-uuid/metrics
req 200 viewer GET "/api/v1/nodes/$NODE/cgk"
[ "$(j .ok)" = true ] || { FAILS=$((FAILS + 1)); echo "FAIL cgk report: $(cat "$TMP/body")"; }
req 200 viewer GET "/api/v1/nodes/$ADOPTED/cgk"
[ "$(cat "$TMP/body")" = null ] || { FAILS=$((FAILS + 1)); echo "FAIL cgk without report: $(cat "$TMP/body")"; }
req 404 viewer GET "/api/v1/nodes/$Z/cgk"
req 404 viewer GET /api/v1/nodes/not-a-uuid/cgk
req 200 viewer GET "/api/v1/nodes/$NODE/config/rendered"
req 404 viewer GET "/api/v1/nodes/$Z/config/rendered"
req 404 viewer GET /api/v1/nodes/not-a-uuid/config/rendered
req 403 viewer PATCH "/api/v1/nodes/$NODE" '{"name":"x"}'
req 200 admin PATCH "/api/v1/nodes/$NODE" '{"overrides":{"cache":{"max_entries":42}}}'
req 422 admin PATCH "/api/v1/nodes/$NODE" '{"overrides":{"cache":{"max_entries":0}}}'
req 422 admin PATCH "/api/v1/nodes/$NODE" '{"overrides":"x"}'
req 200 admin PATCH "/api/v1/nodes/$NODE" '{"overrides":null}'
[ "$(j .overrides)" = '{}' ] || { FAILS=$((FAILS + 1)); echo "FAIL overrides null: $(j .overrides)"; }
req 200 admin PATCH "/api/v1/nodes/$NODE" '{"overrides":{}}'
req 400 admin PATCH "/api/v1/nodes/$NODE" '{"name":"bad name"}'
req 400 admin PATCH "/api/v1/nodes/$NODE" '{"profile_id":"not-a-uuid"}'
req 400 admin PATCH "/api/v1/nodes/$NODE" "{\"profile_id\":\"$Z\"}"
req 400 admin PATCH "/api/v1/nodes/$NODE" '{"labels":{"":"x"}}'
req 400 admin PATCH "/api/v1/nodes/$NODE" 'garbage'
req 200 admin PATCH "/api/v1/nodes/$NODE" '{"name":"ns1-jkt","profile_id":""}'
req 404 admin PATCH "/api/v1/nodes/$Z" '{"name":"x"}'
req 202 admin POST "/api/v1/nodes/$NODE/commands" '{"type":"cgk_refresh"}'
req 422 admin POST "/api/v1/nodes/$NODE/commands" '{"type":"rm"}'
req 422 admin POST "/api/v1/nodes/$NODE/commands" '{"type":"upgrade_dnsdist"}'
req 422 admin POST "/api/v1/nodes/$NODE/commands" '{"type":"reapply","version":"2.0.1-1"}'
req 422 admin POST "/api/v1/nodes/$NODE/commands" '{"type":"set_dnsdist_series","series":"19"}'
req 202 admin POST "/api/v1/nodes/$NODE/commands" '{"type":"set_dnsdist_series","series":"21"}'
req 202 admin POST "/api/v1/nodes/$NODE/commands" '{"type":"check_updates"}'
INV=',"dnsdist_version":"2.0.0-1","dnsdist_available":["2.0.0-1","2.0.1-1"],"dnsdist_candidate":"2.0.1-1","dnsdist_repo_series":"20","inventory_at":"2026-09-27T00:00:00Z"}'
req 200 "$NTOK" POST /agent/v1/heartbeat "${HB%\}}$INV"
[ "$(jq -r '[.commands[] | .series // empty] | join(",")' "$TMP/body")" = 21 ] || { FAILS=$((FAILS + 1)); echo "FAIL command params: $(cat "$TMP/body")"; }
req 200 "$ATOK" POST /agent/v1/heartbeat "${HB%\}}$INV"
req 200 viewer GET "/api/v1/nodes/$NODE/versions"
[ "$(j '.available | length')" = 2 ] || { FAILS=$((FAILS + 1)); echo "FAIL versions: $(cat "$TMP/body")"; }
req 404 viewer GET "/api/v1/nodes/$Z/versions"
req 404 viewer GET /api/v1/nodes/not-a-uuid/versions
req 202 admin POST "/api/v1/nodes/$NODE/commands" '{"type":"upgrade_dnsdist","version":"2.0.1-1"}'
req 422 admin POST "/api/v1/nodes/$NODE/commands" '{"type":"upgrade_dnsdist","version":"9.9"}'
req 404 admin POST "/api/v1/nodes/$Z/commands" '{"type":"reapply"}'
req 404 admin POST /api/v1/nodes/not-a-uuid/commands '{"type":"reapply"}'
req 403 viewer POST "/api/v1/nodes/$NODE/commands" '{"type":"reapply"}'

# ── upgrades (SPEC §18) ──
req 200 viewer GET /api/v1/meta
[ "$(j '.supported_series | length')" -gt 0 ] || { FAILS=$((FAILS + 1)); echo "FAIL meta: $(cat "$TMP/body")"; }
req 200 viewer GET /api/v1/upgrades
req 404 viewer GET /api/v1/upgrades/999
req 404 viewer GET /api/v1/upgrades/x
req 403 viewer POST /api/v1/upgrades '{"kind":"dnsdist","target_version":"2.0.1-1"}'
req 400 admin POST /api/v1/upgrades 'garbage'
req 422 admin POST /api/v1/upgrades '{"kind":"os"}'
req 422 admin POST /api/v1/upgrades '{"kind":"dnsdist","target_version":"9.9"}'
req 422 admin POST /api/v1/upgrades "{\"kind\":\"dnsdist\",\"target_version\":\"2.0.1-1\",\"node_ids\":[\"$Z\"]}"
[ -n "${EXPECT_AGENT:-}" ] || req 422 admin POST /api/v1/upgrades '{"kind":"agent"}' # nothing embedded
req 200 "$NTOK" POST /agent/v1/heartbeat "${HB%\}}$INV" # both nodes fresh and online
# ack the manual upgrade_dnsdist delivered just now, else the node counts as upgrading
req 200 "$NTOK" POST /agent/v1/heartbeat "${HB%\}}${INV%\}},\"acked_commands\":$(jq -c '[.commands[].id]' "$TMP/body")}"
req 200 "$ATOK" POST /agent/v1/heartbeat "${HB%\}}$INV"
req 201 admin POST /api/v1/upgrades '{"kind":"dnsdist","target_version":"2.0.1-1"}'
RUN=$(j .id)
[ "$(j '.steps | length')" = 2 ] || { FAILS=$((FAILS + 1)); echo "FAIL run steps: $(cat "$TMP/body")"; }
req 409 admin POST /api/v1/upgrades '{"kind":"dnsdist","target_version":"2.0.1-1"}'
req 409 admin POST "/api/v1/nodes/$NODE/commands" '{"type":"upgrade_dnsdist","version":"2.0.1-1"}'
req 200 viewer GET "/api/v1/upgrades/$RUN"
req 403 viewer POST "/api/v1/upgrades/$RUN/pause"
req 200 admin POST "/api/v1/upgrades/$RUN/pause"
req 409 admin POST "/api/v1/upgrades/$RUN/pause"
req 200 admin POST "/api/v1/upgrades/$RUN/resume"
req 404 admin POST "/api/v1/upgrades/$RUN/explode"
req 200 admin POST "/api/v1/upgrades/$RUN/abort"
req 409 admin POST "/api/v1/upgrades/$RUN/abort"
req 404 admin POST /api/v1/upgrades/999/abort

# ── blocklist ──
req 200 viewer GET /api/v1/blocklist/sources
for id in $(j '.items[].id'); do # no internet fetches from a smoke test
	req 200 admin PATCH "/api/v1/blocklist/sources/$id" '{"enabled":false}'
done
req 400 admin POST /api/v1/blocklist/sources '{"name":"x","kind":"nope"}'
req 400 admin POST /api/v1/blocklist/sources '{"name":"x","kind":"url_domains","url":"ftp://x"}'
req 400 admin POST /api/v1/blocklist/sources 'garbage'
req 201 admin POST /api/v1/blocklist/sources '{"name":"manual","kind":"manual_domains","content":"bad.example\nworse.example\n"}'
SRC=$(j .id)
req 200 admin PATCH "/api/v1/blocklist/sources/$SRC" '{"content":"bad.example\n"}'
req 404 admin PATCH "/api/v1/blocklist/sources/$Z" '{"enabled":false}'
req 404 admin PATCH /api/v1/blocklist/sources/not-a-uuid '{"enabled":false}'
req 200 viewer GET /api/v1/blocklist/current
req 200 viewer GET /api/v1/blocklist/builds
req 403 viewer POST /api/v1/blocklist/builds
req 202 admin POST /api/v1/blocklist/builds
for _ in $(seq 50); do
	req 200 viewer GET /api/v1/blocklist/current
	[ "$(j .status)" = ok ] && break
	sleep 0.2
done
[ "$(j .status)" = ok ] || { FAILS=$((FAILS + 1)); echo "FAIL build did not finish: $(cat "$TMP/body")"; }
req 200 viewer GET '/api/v1/blocklist/lookup?name=www.bad.example'
[ "$(j .blocked)" = true ] || { FAILS=$((FAILS + 1)); echo "FAIL lookup: $(cat "$TMP/body")"; }
req 200 viewer GET '/api/v1/blocklist/lookup?name=good.example'
req 400 viewer GET /api/v1/blocklist/lookup
req '*' viewer GET '/api/v1/blocklist/lookup?name=%00..'
req 200 "$NTOK" GET /agent/v1/blocklist
req 206 "$NTOK" GET /agent/v1/blocklist '' -H 'Range: bytes=0-9'
SHA=$(curl -s -H "Authorization: Bearer $NTOK" -D - -o /dev/null "$B/agent/v1/blocklist" | tr -d '\r' | awk -F': ' 'tolower($1)=="etag"{print $2}')
req 304 "$NTOK" GET /agent/v1/blocklist '' -H "If-None-Match: $SHA"

# ── allowlist (SPEC §7.5) ──
req 200 viewer GET /api/v1/allowlist
req 403 viewer POST /api/v1/allowlist '{"kind":"domain","value":"bad.example"}'
req 400 admin POST /api/v1/allowlist 'garbage'
req 422 admin POST /api/v1/allowlist '{"kind":"domain","value":"example"}'
req 422 admin POST /api/v1/allowlist '{"kind":"ip","value":"0.0.0.0/0"}'
req 422 admin POST /api/v1/allowlist '{"kind":"cdn","value":"bad.example"}'
req 422 admin POST /api/v1/allowlist '{"kind":"domain","value":"x.example","expires_at":"2020-01-01T00:00:00Z"}'
req 201 admin POST /api/v1/allowlist '{"kind":"domain","value":"Bad.Example.","reason":"shared CDN"}'
ALLOW=$(j .id)
[ "$(j .value)" = bad.example ] || { FAILS=$((FAILS + 1)); echo "FAIL allowlist value: $(cat "$TMP/body")"; }
req 409 admin POST /api/v1/allowlist '{"kind":"domain","value":"bad.example"}'
req 201 admin POST /api/v1/allowlist '{"kind":"ip","value":"192.0.2.0/24","expires_at":"2099-01-01T00:00:00Z"}'
req 200 viewer GET '/api/v1/blocklist/lookup?name=www.bad.example'
[ "$(j '.blocked, .allowed, .allow_entry.value' | paste -sd, -)" = true,true,bad.example ] ||
	{ FAILS=$((FAILS + 1)); echo "FAIL lookup allowed: $(cat "$TMP/body")"; }
req 401 none GET /agent/v1/allowlist
req 200 "$NTOK" GET /agent/v1/allowlist
AV=$(j .version)
[ "$(j '.domains, .ips | join(",")' | paste -sd' ' -)" = "bad.example 192.0.2.0/24" ] || { FAILS=$((FAILS + 1)); echo "FAIL agent allowlist: $(cat "$TMP/body")"; }
req 304 "$NTOK" GET /agent/v1/allowlist '' -H "If-None-Match: \"$AV\""
req 403 viewer DELETE "/api/v1/allowlist/$ALLOW"
req 204 admin DELETE "/api/v1/allowlist/$ALLOW"
req 404 admin DELETE "/api/v1/allowlist/$ALLOW"
req 404 admin DELETE /api/v1/allowlist/not-a-uuid
req 200 "$NTOK" GET /agent/v1/allowlist '' -H "If-None-Match: \"$AV\""
req 204 admin DELETE "/api/v1/blocklist/sources/$SRC"
req 404 admin DELETE "/api/v1/blocklist/sources/$SRC"

# ── reports & offenders ──
req 200 viewer GET /api/v1/reports/blocked
req 200 viewer GET "/api/v1/reports/blocked?from=2026-01-01&to=2026-12-31&node_id=$NODE&limit=10"
req 400 viewer GET '/api/v1/reports/blocked?from=yesterday'
req 400 viewer GET '/api/v1/reports/blocked?node_id=not-a-uuid'
req '*' viewer GET '/api/v1/reports/blocked?limit=-5'
for k in summary monthly top; do req 200 viewer GET "/api/v1/reports/blocked.csv?kind=$k"; done
req 400 viewer GET '/api/v1/reports/blocked.csv?kind=nope'
req 200 viewer GET /api/v1/analytics
[ "$(j '.total, .top[0].name, .top[0].count, (.by_day | length)' | paste -sd, -)" = 20,www.example.com,12,7 ] ||
	{ FAILS=$((FAILS + 1)); echo "FAIL analytics report: $(cat "$TMP/body")"; }
req 200 viewer GET "/api/v1/analytics?from=$TODAY&to=$TODAY&node_id=$NODE&kind=nxdomain&limit=10"
[ "$(j .top[0].share)" = 1 ] || { FAILS=$((FAILS + 1)); echo "FAIL analytics nxdomain share: $(cat "$TMP/body")"; }
for q in from=yesterday kind=nope limit=0 limit=1001 node_id=not-a-uuid 'from=2026-02-01&to=2026-01-01'; do
	req 400 viewer GET "/api/v1/analytics?$q"
done
req 200 viewer GET '/api/v1/analytics.csv?kind=queried_grouped'
req 200 viewer GET /api/v1/analytics.csv
[ "$(head -1 "$TMP/body" | tr -d '\r')" = rank,name,count,share,approximate ] || { FAILS=$((FAILS + 1)); echo "FAIL analytics csv: $(cat "$TMP/body")"; }
req 400 viewer GET '/api/v1/analytics.csv?kind=nope'
req 401 none GET /api/v1/analytics
req 200 viewer GET /api/v1/offenders
req 200 viewer GET "/api/v1/offenders?active=true&node_id=$NODE"
req 400 viewer GET '/api/v1/offenders?node_id=not-a-uuid'

# ── deletes ──
req 409 admin DELETE "/api/v1/profiles/$DEFAULT"
req 204 admin DELETE "/api/v1/profiles/$COPY"
req 404 admin DELETE "/api/v1/profiles/$COPY"
req 404 admin DELETE /api/v1/profiles/not-a-uuid
req 204 admin DELETE "/api/v1/enrollment-tokens/$TOKID"
req 404 admin DELETE "/api/v1/enrollment-tokens/$TOKID"
req 403 viewer DELETE "/api/v1/nodes/$NODE"
req 204 admin DELETE "/api/v1/nodes/$NODE"
req 404 admin DELETE "/api/v1/nodes/$NODE"
req 401 "$NTOK" GET /agent/v1/config
req 204 admin DELETE "/api/v1/users/$VIEWER"
req 401 viewer GET /api/v1/auth/me
req 404 admin DELETE "/api/v1/users/$VIEWER"
req 204 admin POST /api/v1/auth/logout
req 401 admin GET /api/v1/auth/me

if grep -q '"level":"ERROR"' "$TMP/panel.log"; then
	echo "panel logged errors:"; grep '"level":"ERROR"' "$TMP/panel.log"; FAILS=$((FAILS + 1))
fi
echo "smoke: $N requests, $FAILS failure(s)"
[ "$FAILS" = 0 ]
