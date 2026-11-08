// Client-side mirrors of api.ConfigSpec.Validate's per-item checks (the server stays authoritative).
const V4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/
const HOST = /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*\.?$/i

export const isIPv4 = (s: string) => V4.test(s)
export function isIPv6(s: string) {
  if (!s.includes(':') || s.includes('%') || s.includes('[')) return false
  try {
    new URL(`http://[${s}]/`) // the URL parser is a complete IPv6 validator
    return true
  } catch {
    return false
  }
}

/** IPv4-mapped IPv6 (`::ffff:a.b.c.d`, hex or dotted): Go rejects it and dnsdist matches nothing. */
const MAPPED6 = /^\[::ffff:(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|\d{1,3}(?:\.\d{1,3}){3})\]$/

/** IPv6 without the mapped form; dotted tails only where Go allows them (pools). */
function isV6Like(s: string, dottedTail: boolean) {
  if (!s.includes(':') || s.includes('%') || s.includes('[') || (!dottedTail && s.includes('.'))) return false
  try {
    return !MAPPED6.test(new URL(`http://[${s}]/`).hostname)
  } catch {
    return false
  }
}

/** ip-alias target: a plain address. Go rejects zoned, IPv4-mapped and dotted-tail forms. */
export const isAliasTarget = (s: string) => isIPv4(s) || isV6Like(s, false)

/** ip-alias match pool: like isCIDR, but IPv4-mapped pools are rejected (dnsdist's
 *  NetmaskGroup matches nothing for them). Dotted-tail pools are fine: dnsdist matches
 *  them against the hex wire form. */
export function isAliasPool(s: string) {
  const [addr, bits, extra] = s.split('/')
  if (extra !== undefined) return false
  const max = isIPv4(addr) ? 32 : isV6Like(addr, true) ? 128 : -1
  if (max < 0) return false
  return bits === undefined || (/^\d{1,3}$/.test(bits) && Number(bits) <= max)
}

/** CIDR or bare address, like validPrefix in Go. */
export function isCIDR(s: string) {
  const [addr, bits, extra] = s.split('/')
  if (extra !== undefined) return false
  const max = isIPv4(addr) ? 32 : isIPv6(addr) ? 128 : -1
  if (max < 0) return false
  return bits === undefined || (/^\d{1,3}$/.test(bits) && Number(bits) <= max)
}

/** "1.2.3.4:53" or "[::1]:53". */
export function isIPPort(s: string) {
  const m = s.match(/^(?:\[([^\]]+)\]|([^:[\]]+)):(\d{1,5})$/)
  if (!m || Number(m[3]) > 65535) return false
  return m[1] !== undefined ? isIPv6(m[1]) : isIPv4(m[2])
}

export const isHostname = (s: string) => s.length <= 253 && HOST.test(s)

/** Linux network interface name (IFNAMSIZ 15 bytes; VLAN/bond names use '.', '-', ':' and '@'). */
export const isInterface = (s: string) => /^[A-Za-z0-9_.:@-]{1,15}$/.test(s)
