-- Synthetic dnsdist_ootb abuse.lua for tests (documentation ranges only).
local trusted = {
  "127.0.0.1",          -- loopback, bare IP
  "192.0.2.0/24",
  '198.51.100.7',       -- single-quoted, bare IP
  "2001:db8::1",
  "2001:db8:100::/48",
  "not-an-ip",          -- skipped with a warning
  -- "203.0.113.0/24",  commented out
  "::1/128",
}

local dbr = dynBlockRulesGroup()
dbr:setQueryRate(40, 10, "Exceeded query rate", 300, DNSAction.Truncate)
for _, r in ipairs(trusted) do dbr:excludeRange(r) end
function maintenance() dbr:apply() end
