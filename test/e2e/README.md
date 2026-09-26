# End-to-end test

Runs the whole stack on one machine (macOS or Linux) against a **real** dnsdist:

1. fresh Postgres database, `dnsjos migrate`, seeded TrustPositif sources disabled
   (nothing is downloaded from the internet except DNS answers);
2. the panel on `127.0.0.1:18080` with a bootstrap admin;
3. the default profile switched to local listeners: Do53 `127.0.0.1:15353` only,
   DoH/DoT off, webserver `127.0.0.1:18083`, upstreams `1.1.1.1:53` + `8.8.8.8:53`;
4. **adoption dry run** (`adopt` subtest) while the panel has no blocklist build: a fake
   root holding `internal/agent/testdata/dnsdist-ootb.yml` (test secrets, self-signed cert) and
   a synthetic `abuse.lua` (`internal/agent/testdata/abuse.lua`) and an old `db/blacklist.db` → `dnsjos-agent enroll --adopt` → `dnsjos-agent plan`; checks
   the imported secrets, the stored node overrides, `nodes.adopted`, the seeded CDB
   (409 `no_blocklist` → seed → heartbeat → config), `check-config: OK`, the diff, and
   that nothing was swapped;
5. a local fake blocklist source (`blocked.example`, `pornhub.com`, IP `1.1.1.1`) and
   "build now";
6. the agent: `enroll` + `run --root <tmp> --no-systemd --flush-interval 5s`. There is no systemd, so the test
   plays it: it (re)starts `dnsdist --supervised -C <root>/etc/dnsdist/dnsdist.conf`
   whenever the agent re-renders the files.

Assertions (`dig @127.0.0.1 -p 15353`): normal name resolves; `blocked.example` A/AAAA →
blockpage; `www.pornhub.com` (subdomain) → blockpage; HTTPS type → NOERROR with no
answers; `one.one.one.one` A → `1.1.1.1` rewritten to the blockpage (response-IP
blocking, opted in by the test profile); the panel's live heartbeat shows dnsdist running, non-zero queries and blocked
counters, both backends up and the applied config; the CDB file and heartbeat sha256
match the build; `cgkReload()` via the agent's console client; dnstap → `POST /blocked` →
`GET /api/v1/reports/blocked` lists `blocked.example`; a blocked batch posted twice with the same
`Idempotency-Key` is counted once; a newly published version is
re-rendered, dnsdist restarted and the new blockpage served; after a few more queries
(including the NXDOMAIN `nonexistent-e2e.example.invalid`) the analytics dnstap stream →
`POST /agent/v1/analytics` → `GET /api/v1/analytics` shows a non-zero total, the names in
the raw top, `example.com` in the grouped top and the NXDOMAIN name in the nxdomain top; one more query raises a name's count by exactly one
under cumulative tops and it stays there over later flushes.

## Requirements

`dnsdist` (2.0 or 2.1), `dig`, `createdb`/`dropdb`/`psql` against `127.0.0.1:5432` as
`$USER`, outbound DNS to 1.1.1.1/8.8.8.8, and free ports 15353, 18080, 18083, 5199
(console), 6000 (blocked dnstap) and 6001 (analytics dnstap).

## Run

```sh
cd test/e2e
GOTOOLCHAIN=go1.25.0 go test -tags e2e -count=1 -v -timeout 12m .
E2E_LOGS=1 GOTOOLCHAIN=go1.25.0 go test -tags e2e -count=1 -v .   # also print panel/agent/dnsdist logs
```

About 40 s. The database is dropped afterwards.
