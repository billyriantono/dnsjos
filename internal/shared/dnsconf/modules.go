package dnsconf

import (
	"fmt"
	"net/netip"
	"path"
	"strings"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// ripSlots bounds how many A records per response are checked against the IP list.
// ponytail: 8 covers real answers; raise it if blocked IPs hide behind longer RRsets.
const ripSlots = 8

// readListLua reads a one-entry-per-line file ('#' comments) shared by the modules.
const readListLua = `local function readList(path, fallback, allowEmpty)
  local f = io.open(path, "r")
  if not f then return fallback end
  local t = {}
  for line in f:lines() do
    line = line:gsub("#.*", ""):match("^%s*(.-)%s*$")
    if line ~= "" then t[#t + 1] = line end
  end
  f:close()
  if #t == 0 and not allowEmpty then return fallback end
  return t
end
`

// skipNameLua is shared by the response parsers (Lua 1-based offsets).
const skipNameLua = `local function skipName(p, pos)
  while true do
    local len = p:byte(pos)
    if not len then return nil end
    if len == 0 then return pos + 1 end
    if len >= 192 then return pos + 2 end
    pos = pos + len + 1
  end
end
`

func renderBlocking(b api.Blocking, rt api.NodeRuntime) ([]byte, error) {
	v4, err := netip.ParseAddr(b.BlockpageIPv4)
	if err != nil || !v4.Is4() {
		return nil, fmt.Errorf("blocking.blockpage_ipv4: %q is not IPv4", b.BlockpageIPv4)
	}
	v6, err := netip.ParseAddr(b.BlockpageIPv6)
	if err != nil || !v6.Is6() {
		return nil, fmt.Errorf("blocking.blockpage_ipv6: %q is not IPv6", b.BlockpageIPv6)
	}
	soa, err := soaWire(b.SOA)
	if err != nil {
		return nil, err
	}
	ns, err := dnsWire(b.NS)
	if err != nil {
		return nil, fmt.Errorf("blocking.ns: %w", err)
	}
	if len(b.TXT) > 255 {
		return nil, fmt.Errorf("blocking.txt: max 255 characters")
	}

	var s strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&s, format, a...) }
	s.WriteString(Header)
	s.WriteString(`-- Blocklist: names in the CDB (and every name below them) get the blockpage.
declareMetric("dnsjos-blocked", "counter", "Queries answered with the blockpage")
`)
	w("local kvs = newCDBKVStore(%s, 60)\n", luaString(rt.CDBPath))
	w(`
-- Allowlist (emergency unblock of false positives such as CDN names): names in
-- ALLOW_DOMAINS_FILE, and every name below them, are never blocked; addresses in
-- ALLOW_IPS_FILE never trigger the response-IP block. The agent rewrites both files
-- and calls dnsjosAllowReload() over the console; a missing file is an empty list.
local ALLOW_DOMAINS_FILE = %s
local ALLOW_IPS_FILE = %s
`, luaString(path.Join(rt.BaseDir, FileAllowDomains)), luaString(path.Join(rt.BaseDir, FileAllowIPs)))
	s.WriteString(readListLua)
	// SuffixMatchNodeRule copies its SMN, so a reload could not update it; the set lives
	// in a Lua upvalue swapped by dnsjosAllowReload() and is checked only for CDB hits.
	s.WriteString(`local allowSMN, allowNMG, allowNames, allowMasks, allowIPs = newSuffixMatchNode(), newNMG(), {}, {}, 0

function dnsjosAllowReload()
  local smn, nmg, names, masks, nd, ni, bad = newSuffixMatchNode(), newNMG(), {}, {}, 0, 0, 0
  for _, n in ipairs(readList(ALLOW_DOMAINS_FILE, {}, true)) do
    local ok, dn = pcall(newDNSName, n)
    if ok then smn:add(dn); names[n] = dn; nd = nd + 1 else bad = bad + 1 end
  end
  for _, m in ipairs(readList(ALLOW_IPS_FILE, {}, true)) do
    if pcall(function() nmg:addMask(m) end) then masks[m] = true; ni = ni + 1 else bad = bad + 1 end
  end
  -- Cached answers must not outlive the change: a newly allowed name may still have a
  -- blocked answer cached. Queries are checked before the cache, but response-IP
  -- rewrites are not re-applied to cache hits, so a removed entry flushes too (a
  -- removed address can hide behind any name: the whole cache).
  local cache = getPool(""):getCache()
  if cache then
    local all = false
    for m in pairs(allowMasks) do all = all or not masks[m] end
    if all then
      cache:expunge(0)
    else
      for n, dn in pairs(names) do
        if not allowNames[n] then cache:expungeByName(dn, DNSQType.ANY, true) end
      end
      for n, dn in pairs(allowNames) do
        if not names[n] then cache:expungeByName(dn, DNSQType.ANY, true) end
      end
    end
  end
  allowSMN, allowNMG, allowNames, allowMasks, allowIPs = smn, nmg, names, masks, ni
  return string.format("allowlist: %d domains, %d ips, %d invalid", nd, ni, bad)
end
dnsjosAllowReload()

-- A fresh TagRule per rule: dnsdist counts matches on the selector object, so a
-- shared one would make every rule's hit counter the sum of all of them.
local function blocked() return TagRule("dnsjos", "blocked") end
addAction(KeyValueStoreLookupRule(kvs, KeyValueLookupKeySuffix(0, true)), SetTagAction("dnsjos", "blocked"), {name = "dnsjos-blocklist"})
addAction(AndRule({blocked(), LuaRule(function(dq) return allowSMN:check(dq.qname) end)}), SetTagAction("dnsjos", "allowed"), {name = "dnsjos-allowlist"})
addAction(blocked(), LuaAction(function() incMetric("dnsjos-blocked") return DNSAction.None, "" end), {name = "dnsjos-blocked-count"})
`)
	if b.LogBlocked {
		w("local dnstap = newFrameStreamTcpLogger(%s)\n", luaString(rt.DnstapAddr))
		w("addAction(blocked(), DnstapLogAction(%s, dnstap), {name = \"dnsjos-blocked-log\"})\n", luaString(rt.Hostname))
	}
	s.WriteString("\n-- Answers; every qtype not listed gets NODATA (so HTTPS/SVCB/ANY resolve nothing).\n")
	answer := func(qtype, action string) {
		w("addAction(AndRule({blocked(), QTypeRule(DNSQType.%s)}), %s, {name = \"dnsjos-block-%s\"})\n", qtype, action, strings.ToLower(qtype))
	}
	answer("A", "SpoofAction("+luaString(v4.String())+")")
	answer("AAAA", "SpoofAction("+luaString(v6.String())+")")
	if b.TXT != "" {
		answer("TXT", "SpoofRawAction("+luaString(string([]byte{byte(len(b.TXT))})+b.TXT)+", {ttl = 60})")
	}
	answer("SOA", "SpoofRawAction("+luaString(string(soa))+")")
	answer("NS", "SpoofRawAction("+luaString(string(ns))+")")
	s.WriteString(`addAction(blocked(), RCodeAction(DNSRCode.NOERROR), {name = "dnsjos-block-nodata"})
`)

	if b.BlockResponseIPs {
		a4 := v4.As4()
		w(`
-- Response IPs: when any A record's address is in the CDB (key = dotted quad in wire
-- form), EVERY A record in the answer is rewritten to the blockpage with TTL 60, so the
-- client never gets a mix of blockpage and real addresses. The rewritten answer is not
-- cached: each one is counted/logged and CDB updates apply at once. Only A answers are
-- checked (the IP list is IPv4-only). kvs:lookup() cannot tell a missing key from an
-- empty value, so each candidate goes into a tag and a native KeyValueStoreLookupRule
-- decides.
declareMetric("dnsjos-response-ip-blocked", "counter", "Answers rewritten to the blockpage because an A record is listed")
local BLOCKPAGE4 = %s
`, luaString(string(a4[:])))
		s.WriteString(skipNameLua)
		w(`addResponseAction(AndRule({RCodeRule(DNSRCode.NOERROR), QTypeRule(DNSQType.A)}), LuaResponseAction(function(dr)
  local p = dr:getContent()
  if #p < 12 then return DNSResponseAction.None, "" end
  local qd = p:byte(5) * 256 + p:byte(6)
  local an = p:byte(7) * 256 + p:byte(8)
  local pos, at = 13, {}
  for _ = 1, qd do
    pos = skipName(p, pos)
    if not pos then return DNSResponseAction.None, "" end
    pos = pos + 4
  end
  for _ = 1, an do
    pos = skipName(p, pos)
    if not pos or pos + 9 > #p then break end
    local rtype = p:byte(pos) * 256 + p:byte(pos + 1)
    local rdlen = p:byte(pos + 8) * 256 + p:byte(pos + 9)
    local rd = pos + 10
    if rtype == 1 and rdlen == 4 and rd + 3 <= #p then
      at[#at + 1] = rd
      if #at <= %d and (allowIPs == 0 or not allowNMG:match(newCA(string.format("%%d.%%d.%%d.%%d", p:byte(rd, rd + 3))))) then
        local key = {}
        for i = 0, 3 do
          local o = tostring(p:byte(rd + i))
          key[#key + 1] = string.char(#o) .. o
        end
        dr:setTag("dnsjos-rip" .. #at, table.concat(key) .. "\000")
      end
    end
    pos = rd + rdlen
  end
  if #at > 0 then dr:setTag("dnsjos-ripat", table.concat(at, ",")) end
  return DNSResponseAction.None, ""
end), {name = "dnsjos-response-ip-scan"})
-- rdata offsets are 1-based; the TTL sits 6 bytes before the rdata, rdlength 2 before.
local function ripRewrite(dr)
  if dr:getTag("dnsjos") == "ipblocked" or allowSMN:check(dr.qname) then return DNSResponseAction.None, "" end
  local p = dr:getContent()
  local out, last = {}, 1
  for rd in dr:getTag("dnsjos-ripat"):gmatch("%%d+") do
    rd = tonumber(rd)
    if rd - 6 < last or rd + 3 > #p then return DNSResponseAction.None, "" end
    out[#out + 1] = p:sub(last, rd - 7)
    out[#out + 1] = "\000\000\000\060"
    out[#out + 1] = p:sub(rd - 2, rd - 1)
    out[#out + 1] = BLOCKPAGE4
    last = rd + 4
  end
  if last == 1 then return DNSResponseAction.None, "" end
  out[#out + 1] = p:sub(last)
  dr:setContent(table.concat(out))
  dr:setTag("dnsjos", "ipblocked")
  incMetric("dnsjos-response-ip-blocked")
  return DNSResponseAction.None, ""
end
for i = 1, %d do
  addResponseAction(KeyValueStoreLookupRule(kvs, KeyValueLookupKeyTag("dnsjos-rip" .. i)), LuaResponseAction(ripRewrite), {name = "dnsjos-response-ip-" .. i})
end
addResponseAction(TagRule("dnsjos", "ipblocked"), SetSkipCacheResponseAction(), {name = "dnsjos-response-ip-nocache"})
`, ripSlots, ripSlots)
		if b.LogBlocked {
			w("addResponseAction(TagRule(\"dnsjos\", \"ipblocked\"), DnstapLogResponseAction(%s, dnstap), {name = \"dnsjos-response-ip-log\"})\n", luaString(rt.Hostname))
		}
	}
	return []byte(s.String()), nil
}

var dynActions = map[string]string{"truncate": "DNSAction.Truncate", "drop": "DNSAction.Drop", "refused": "DNSAction.Refused"}

func renderAbuse(a api.Abuse) ([]byte, error) {
	action, ok := dynActions[a.DynAction]
	if !ok {
		return nil, fmt.Errorf("abuse.dyn_action: unknown %q", a.DynAction)
	}
	trusted, err := prefixes(a.Trusted)
	if err != nil {
		return nil, fmt.Errorf("abuse.trusted: %w", err)
	}
	// Warn at half the rate; dnsdist ignores a warning rate that is not below the rate.
	warn := func(rate int) int {
		if w := (rate + 1) / 2; w < rate {
			return w
		}
		return 0
	}
	var s strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&s, format, a...) }
	s.WriteString(Header)
	w(`-- Abusive / infected clients, per client IP:
--  1. hard cap: queries ABOVE the rate are dropped, everything below is answered.
--  2. dynamic blocks for sustained floods (warnings at half the rate).
local trusted = %s
local trustedNMG = newNMG()
for _, r in ipairs(trusted) do trustedNMG:addMask(r) end

-- MaxQPSIPRule matches clients OVER the rate: never wrap it in NotRule.
addAction(AndRule({NotRule(NetmaskGroupRule(trustedNMG)), MaxQPSIPRule(%d, 32, 64, %d)}), DropAction(), {name = "per-client-qps-cap"})
mvRuleToTop()

local dbr = dynBlockRulesGroup()
dbr:setQueryRate(%d, %d, "query flood (likely infected device)", %d, %s, %d)
dbr:setRCodeRate(DNSRCode.NXDOMAIN, %d, %d, "NXDOMAIN flood (random-subdomain / DGA malware)", %d, %s, %d)
dbr:setRCodeRate(DNSRCode.SERVFAIL, %d, %d, "SERVFAIL flood (random-subdomain attack)", %d, %s, %d)
`, luaList(trusted), a.PerClientQPS, a.PerClientBurst,
		a.DynQueryRate, a.DynWindowS, a.DynBlockS, action, warn(a.DynQueryRate),
		a.DynNXDomainRate, a.DynWindowS, a.DynBlockS, action, warn(a.DynNXDomainRate),
		a.DynServfailRate, a.DynWindowS, a.DynBlockS, action, warn(a.DynServfailRate))
	if len(trusted) > 0 {
		s.WriteString("dbr:excludeRange(trusted)\n")
	}
	// addMaintenanceCallback instead of maintenance() so extra_lua may define its own.
	s.WriteString("addMaintenanceCallback(function() dbr:apply() end)\n")
	return []byte(s.String()), nil
}

// fallbackAliases are CGK alias IPs measured in production (2026-09); only those
// inside the spec's alias pools are embedded as the fallback.
var fallbackAliases = []string{
	"104.19.240.127", "104.17.62.133", "104.17.48.2", "104.19.164.27",
	"172.64.81.207", "104.19.99.13", "104.18.129.121", "104.16.181.84",
}

func renderCGK(g api.CGK, rt api.NodeRuntime) ([]byte, error) {
	all, err := prefixes(g.RewritePools)
	if err != nil {
		return nil, fmt.Errorf("cgk.rewrite_pools: %w", err)
	}
	// IPv6 ranges are never a fallback: AAAA answers are only rewritten once the agent has
	// measured IPv6 from this node and written its IPv6 aliases.
	var rewrite []string
	for _, p := range all {
		if netip.MustParsePrefix(p).Addr().Is4() {
			rewrite = append(rewrite, p)
		}
	}
	pools, err := prefixes(g.AliasPools)
	if err != nil {
		return nil, fmt.Errorf("cgk.alias_pools: %w", err)
	}
	var aliases []string
	for _, a := range fallbackAliases {
		ip := netip.MustParseAddr(a)
		for _, p := range pools {
			if netip.MustParsePrefix(p).Contains(ip) {
				aliases = append(aliases, a)
				break
			}
		}
	}
	exclude := make([]string, len(g.Exclude))
	for i, e := range g.Exclude {
		exclude[i] = strings.ToLower(strings.TrimSuffix(e, "."))
	}

	var s strings.Builder
	s.WriteString(Header)
	fmt.Fprintf(&s, `-- Cloudflare -> CGK (Jakarta). A records inside the rewrite ranges are swapped
-- for CGK alias IPs (stable per qname); names under EXCLUDE keep their real IPs.
-- The agent's CGK prober maintains both files and calls cgkReload(); the lists
-- below are only the fallback when a file is missing. LEARNED_FILE lists names the agent
-- found broken through an alias (Spectrum, IP-bound apps): those are never rewritten.
local ALIAS_FILE = %s
local ALIAS6_FILE = %s
local REWRITE_FILE = %s
local LEARNED_FILE = %s
local DEFAULT_REWRITE = %s
local DEFAULT_ALIASES = %s
local EXCLUDE = %s
`, luaString(path.Join(rt.BaseDir, FileCGKAliases)), luaString(path.Join(rt.BaseDir, FileCGKAliases6)),
		luaString(path.Join(rt.BaseDir, FileCGKRewrite)), luaString(path.Join(rt.BaseDir, FileCGKLearned)),
		luaList(rewrite), luaList(aliases), luaList(exclude))
	s.WriteString(`
declareMetric("cgk-rewrites", "counter", "DNS answers rewritten to Cloudflare CGK aliases")
declareMetric("cgk-aliases", "gauge", "Cloudflare CGK alias IPs currently in use")
declareMetric("cgk-rewrite-ranges", "gauge", "Cloudflare ranges currently rewritten to CGK")

-- A missing file means "use the fallback"; for the rewrite ranges an existing
-- but empty file means "rewrite nothing" (every pool is already served by CGK).
`)
	s.WriteString(readListLua)
	s.WriteString(`
-- parse6 turns an IPv6 address into its 16 bytes (nil when malformed).
local function parse6(s)
  local function split(x)
    local t = {}
    for g in x:gmatch("[^:]+") do t[#t + 1] = g end
    return t
  end
  local groups
  local head, tail = s:match("^([%x:]-)::([%x:]*)$")
  if head then
    local h, t = split(head), split(tail)
    if #h + #t > 7 then return nil end
    groups = h
    for _ = 1, 8 - #h - #t do groups[#groups + 1] = "0" end
    for _, g in ipairs(t) do groups[#groups + 1] = g end
  else
    groups = split(s)
  end
  if #groups ~= 8 then return nil end
  local b = {}
  for _, g in ipairs(groups) do
    if #g > 4 or not g:match("^%x+$") then return nil end
    local v = tonumber(g, 16)
    b[#b + 1] = string.char(math.floor(v / 256), v % 256)
  end
  return table.concat(b)
end

-- ip6str formats the 16 bytes of p starting at i (uncompressed, for newCA and logs).
local function ip6str(p, i)
  local g = {}
  for k = 0, 7 do g[#g + 1] = string.format("%x", p:byte(i + 2 * k) * 256 + p:byte(i + 2 * k + 1)) end
  return table.concat(g, ":")
end

local rewriteNMG, aliasBytes, alias6Bytes, learned = newNMG(), {}, {}, {}

-- (Re)load the lists; called by the agent over the console: cgkReload()
function cgkReload()
  local nmg, bytes, bytes6, skip = newNMG(), {}, {}, {}
  for _, ip in ipairs(readList(ALIAS6_FILE, {}, true)) do
    local b = parse6(ip)
    if b then bytes6[#bytes6 + 1] = b end
  end
  local names = readList(LEARNED_FILE, {}, true)
  for _, n in ipairs(names) do skip[n:lower()] = true end
  learned = skip
  local ranges = readList(REWRITE_FILE, DEFAULT_REWRITE, true)
  for _, n in ipairs(ranges) do nmg:addMask(n) end
  for _, ip in ipairs(readList(ALIAS_FILE, DEFAULT_ALIASES)) do
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if a then bytes[#bytes + 1] = string.char(tonumber(a), tonumber(b), tonumber(c), tonumber(d)) end
  end
  if #bytes == 0 then return "cgk: no valid aliases, keeping previous lists" end
  rewriteNMG, aliasBytes, alias6Bytes = nmg, bytes, bytes6
  setMetric("cgk-aliases", #bytes + #bytes6)
  setMetric("cgk-rewrite-ranges", #ranges)
  return string.format("cgk: %d aliases, %d IPv6 aliases, %d rewrite ranges, %d learned exclusions", #bytes, #bytes6, #ranges, #names)
end
cgkReload()

-- Rewritten names since the last cgkSeen(): name -> {real IP, alias IP, count}. Bounded:
-- once full, new names wait for the next drain (every 10 min).
local seen, seenN, SEEN_MAX = {}, 0, 2000

-- Called by the agent over the console: "name real-ip alias-ip count" lines, then reset.
function cgkSeen()
  local out = {}
  for n, e in pairs(seen) do out[#out + 1] = string.format("%s %s %s %d", n, e[1], e[2], e[3]) end
  seen, seenN = {}, 0
  return table.concat(out, "\n")
end

local excludeSMN = newSuffixMatchNode()
for _, n in ipairs(EXCLUDE) do excludeSMN:add(newDNSName(n)) end

`)
	s.WriteString(skipNameLua)
	s.WriteString(`
local function cgkRewrite(dr)
  local p = dr:getContent()
  if #p < 12 then return DNSResponseAction.None, "" end
  local qd = p:byte(5) * 256 + p:byte(6)
  local an = p:byte(7) * 256 + p:byte(8)
  if an == 0 then return DNSResponseAction.None, "" end
  local pos = 13
  for _ = 1, qd do
    pos = skipName(p, pos)
    if not pos then return DNSResponseAction.None, "" end
    pos = pos + 4
  end
  -- stable per name, so a site keeps the same aliases across queries
  local s, h = dr.qname:toString(), 0
  local name = s:lower():gsub("%.$", "")
  if learned[name] then -- keep counting it (IPs "-") so the agent knows it is still in use
    local e = seen[name]
    if e then e[3] = e[3] + 1 elseif seenN < SEEN_MAX then seen[name], seenN = { "-", "-", 1 }, seenN + 1 end
    return DNSResponseAction.None, ""
  end
  for i = 1, #s do h = (h * 31 + s:byte(i)) % 2147483647 end
  local nmg, aliases, aliases6 = rewriteNMG, aliasBytes, alias6Bytes
  if #aliases == 0 and #aliases6 == 0 then return DNSResponseAction.None, "" end
  local edits, k, realIP = {}, 0, nil
  for _ = 1, an do
    pos = skipName(p, pos)
    if not pos or pos + 9 > #p then break end
    local rtype = p:byte(pos) * 256 + p:byte(pos + 1)
    local rdlen = p:byte(pos + 8) * 256 + p:byte(pos + 9)
    local rd = pos + 10
    if rtype == 1 and rdlen == 4 and rd + 3 <= #p and #aliases > 0 then
      local ip = string.format("%d.%d.%d.%d", p:byte(rd, rd + 3))
      if nmg:match(newCA(ip)) then
        realIP = realIP or ip
        edits[#edits + 1] = { rd, aliases[((h + k) % #aliases) + 1] }
        k = k + 1
      end
    elseif rtype == 28 and rdlen == 16 and rd + 15 <= #p and #aliases6 > 0 then
      local ip = ip6str(p, rd)
      if nmg:match(newCA(ip)) then
        realIP = realIP or ip
        edits[#edits + 1] = { rd, aliases6[((h + k) % #aliases6) + 1] }
        k = k + 1
      end
    end
    pos = rd + rdlen
  end
  if #edits == 0 then return DNSResponseAction.None, "" end
  local out, last = {}, 1
  for _, e in ipairs(edits) do
    out[#out + 1] = p:sub(last, e[1] - 1)
    out[#out + 1] = e[2]
    last = e[1] + #e[2]
  end
  out[#out + 1] = p:sub(last)
  dr:setContent(table.concat(out))
  incMetric("cgk-rewrites")
  local e = seen[name]
  if e then
    e[3] = e[3] + 1
  elseif seenN < SEEN_MAX then
    local a = edits[1][2]
    seen[name] = { realIP, #a == 4 and string.format("%d.%d.%d.%d", a:byte(1, 4)) or ip6str(a, 1), 1 }
    seenN = seenN + 1
  end
  return DNSResponseAction.None, ""
end

addResponseAction(AndRule({RCodeRule(DNSRCode.NOERROR), OrRule({QTypeRule(DNSQType.A), QTypeRule(DNSQType.AAAA)}),
                          NotRule(SuffixMatchNodeRule(excludeSMN, true))}),
                  LuaResponseAction(cgkRewrite), {name = "cloudflare-cgk"})
`)
	return []byte(s.String()), nil
}

func renderDualStack(rt api.NodeRuntime) []byte {
	var s strings.Builder
	s.WriteString(Header)
	fmt.Fprintf(&s, `-- Dual-stack selection, smartdns' dualstack-ip-selection (SPEC §6.8). The agent
-- measures the names dsSeen() reports over IPv4 and IPv6 and lists the losers:
-- PREFER_V4_FILE (AAAA dropped) and PREFER_V6_FILE (A dropped, allow_force_aaaa), one
-- "name ttl" per line, then calls dsReload(). A dropped answer is what smartdns sends:
-- NODATA with an SOA for the name in the authority section, TTL = the real record's.
local PREFER_V4_FILE = %s
local PREFER_V6_FILE = %s

declareMetric("dualstack-suppressed", "counter", "A/AAAA queries answered NODATA because the other family is faster")
declareMetric("dualstack-names", "gauge", "Names currently answered over one address family only")
`, luaString(path.Join(rt.BaseDir, FileDualStackPreferV4)), luaString(path.Join(rt.BaseDir, FileDualStackPreferV6)))
	s.WriteString(readListLua)
	s.WriteString(`
local drop = { [1] = {}, [28] = {} } -- qtype -> name -> TTL

-- Called by the agent over the console: dsReload()
function dsReload()
  local function load(file)
    local t, n = {}, 0
    for _, l in ipairs(readList(file, {}, true)) do
      local name, ttl = l:match("^(%S+)%s+(%d+)$")
      if name then t[name:lower()], n = tonumber(ttl), n + 1 end
    end
    return t, n
  end
  local v4, n4 = load(PREFER_V4_FILE)
  local v6, n6 = load(PREFER_V6_FILE)
  drop = { [1] = v6, [28] = v4 }
  setMetric("dualstack-names", n4 + n6)
  return string.format("dualstack: %d names prefer IPv4, %d prefer IPv6", n4, n6)
end
dsReload()

-- Names with AAAA answers (or dropped queries) since the last dsSeen(): name -> count.
-- Bounded: once full, new names wait for the next drain (every 10 min).
local seen, seenN, SEEN_MAX = {}, 0, 2000
local function note(name)
  local n = seen[name]
  if n then seen[name] = n + 1 elseif seenN < SEEN_MAX then seen[name], seenN = 1, seenN + 1 end
end

-- Called by the agent over the console: "name count" lines, then reset.
function dsSeen()
  local out = {}
  for n, c in pairs(seen) do out[#out + 1] = string.format("%s %d", n, c) end
  seen, seenN = {}, 0
  return table.concat(out, "\n")
end

local function u16(n) return string.char(math.floor(n / 256) % 256, n % 256) end
local function u32(n) return u16(math.floor(n / 65536)) .. u16(n % 65536) end
-- smartdns' SOA (_dns_server_setup_soa): a.gtld-servers.net. nstld.verisign-grs.com. 1800 1800 900 604800 86400
local SOA_RDATA = "\1a\12gtld-servers\3net\0" .. "\5nstld\12verisign-grs\3com\0" ..
  u32(1800) .. u32(1800) .. u32(900) .. u32(604800) .. u32(86400)

addAction(OrRule({QTypeRule(DNSQType.A), QTypeRule(DNSQType.AAAA)}), LuaAction(function(dq)
  local name = dq.qname:toStringNoDot():lower()
  local ttl = drop[dq.qtype][name]
  if not ttl then return DNSAction.None, "" end
  local q = dq:getContent()
  local pos = 13 -- end of the question (the query's qname is never compressed)
  while pos <= #q and q:byte(pos) ~= 0 do pos = pos + q:byte(pos) + 1 end
  if pos + 4 > #q then return DNSAction.None, "" end
  note(name) -- still asked for: the agent keeps re-measuring it
  incMetric("dualstack-suppressed")
  -- QR + the query's RD, RA; 1 question, 1 authority record: SOA owned by the qname (pointer to offset 12)
  dq:setContent(q:sub(1, 2) .. string.char(128 + q:byte(3) % 2, 128) .. u16(1) .. u16(0) .. u16(1) .. u16(0) ..
    q:sub(13, pos + 4) .. "\192\12" .. u16(6) .. u16(1) .. u32(ttl) .. u16(#SOA_RDATA) .. SOA_RDATA)
  return DNSAction.HeaderModify, ""
end), {name = "dnsjos-dualstack-select"})

addResponseAction(AndRule({RCodeRule(DNSRCode.NOERROR), QTypeRule(DNSQType.AAAA)}),
  LuaResponseAction(function(dr)
    local p = dr:getContent()
    if #p >= 12 and p:byte(7) * 256 + p:byte(8) > 0 then note(dr.qname:toStringNoDot():lower()) end
    return DNSResponseAction.None, ""
  end), {name = "dnsjos-dualstack-seen"})
`)
	return []byte(s.String())
}
