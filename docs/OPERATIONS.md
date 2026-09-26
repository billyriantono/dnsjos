# Operations

## Adding a new node

Nodes → Add node → copy the install command and run it on a fresh Debian 12/13 or
Ubuntu 22.04/24.04 host:

```sh
curl -fsSL https://panel.example/install.sh | sudo sh -s -- --token TOKEN
```

The installer installs dnsdist 2.0 from repo.powerdns.com only when dnsdist is **not**
installed; an existing dnsdist is never upgraded. Add `--no-start` to review the first
config before the agent touches dnsdist (see `plan` below).

## Adopting a live dnsdist server (rolling, zero customer downtime)

Live servers run dnsdist with the dnsdist_ootb YAML wrapper. Adoption keeps the dnsdist
package, the webserver password/API key and console key (Prometheus/Grafana scrapes and
`dnsdist-offenders` keep working), the webserver listen address + ACL, the DoH/DoT
certificates and the Do53 listen addresses. ACL, upstreams, blocking, abuse and CGK come
from the profile — the `default` profile equals the production values.

**One node at a time, least busy first.** Before each node confirm in the panel that every
other node is `online`.

1. Panel → Nodes → Add node → create a token (pick the profile, normally `default`).
2. On the node:

   ```sh
   curl -fsSL https://panel.example/install.sh | sudo sh -s -- --token TOKEN --adopt --no-start
   ```

   `--adopt` skips the PowerDNS repo, any dnsdist install/upgrade and the
   systemd-resolved changes, backs up `/etc/dnsdist` to `/var/lib/dnsjos/pre-install-<ts>/`
   and runs `dnsjos-agent enroll --adopt`, which imports the secrets from
   `/etc/dnsdist/dnsdist.yml` into `/var/lib/dnsjos/secrets.json` and sends the
   node-specific settings as node overrides (visible on the node page).
3. Review what the agent would do — nothing is swapped or restarted:

   ```sh
   dnsjos-agent plan
   ```

   It prints the effective listeners, ACL size, upstreams + weights, blocking, abuse, CGK,
   webserver and blocklist, runs `dnsdist --check-config` on the rendered files in
   `/etc/dnsdist/.dnsjos-staging/` and shows a unified diff against `/etc/dnsdist/`. If the
   panel has no blocklist build yet, `plan` seeds the agent CDB from
   `/etc/dnsdist/db/blacklist.db` and reports it, so the panel hands out the config.
   Fix anything unexpected with node overrides (node page) and re-run `plan`.
4. Start the agent:

   ```sh
   systemctl enable --now dnsjos-agent
   journalctl -u dnsjos-agent -f
   ```

   On the first apply the agent archives the whole `/etc/dnsdist` (dnsdist_ootb, old CDB)
   to `/var/lib/dnsjos/pre-adopt-<ts>.tar.gz`, seeds the CDB (panel build, else the old
   `db/blacklist.db`), then checks, swaps, restarts dnsdist and waits for its console. If
   dnsdist does not come back, the tree is restored **exactly** from the archive and
   dnsdist restarted; the node shows the apply error. The dnsdist restart is the only
   interruption (a second or two for this node).
5. Verify before moving on (replace `NODE`):

   ```sh
   dig @NODE example.com +short                  # resolves
   dig @NODE <a blocked domain> +short           # your blockpage IPv4
   dig @NODE <a blocked domain> AAAA +short      # your blockpage IPv6
   dig @NODE <a blocked domain> HTTPS            # NOERROR, ANSWER: 0
   kdig @NODE +https example.com; kdig @NODE +tls example.com   # DoH / DoT, if enabled
   ```

   In the panel: the node is `online`, backends up, config and blocklist in sync; the
   blocked query shows up in Reports → Blocked within ~2 minutes (dnstap → agent → panel);
   Grafana still scrapes the node (same webserver address, password and API key).
6. Continue with the next node.

### Manual rollback

```sh
systemctl stop dnsjos-agent
tar -tzf /var/lib/dnsjos/pre-adopt-<ts>.tar.gz >/dev/null   # archive readable
rm -rf /etc/dnsdist && mkdir /etc/dnsdist
tar -C /etc/dnsdist -xpzf /var/lib/dnsjos/pre-adopt-<ts>.tar.gz
systemctl restart dnsdist
systemctl disable dnsjos-agent
```

Later config changes keep the last five managed-file backups in `/var/lib/dnsjos/backup/`.

## Files on a node

| Path | What |
|---|---|
| `/etc/dnsjos/agent.json` | panel URL, node id, node token (0600) |
| `/var/lib/dnsjos/secrets.json` | console key, webserver password + API key (0600) |
| `/var/lib/dnsjos/blocklist/current.cdb` | blocklist read by dnsdist |
| `/var/lib/dnsjos/blocked-spool/` | blocked-query batches not yet accepted by the panel |
| `/var/lib/dnsjos/pre-adopt-<ts>.tar.gz` | `/etc/dnsdist` before the first dnsjos apply |
| `/etc/dnsdist/dnsdist.conf`, `/etc/dnsdist/dnsjos/*.lua` | rendered by the agent — do not edit |
