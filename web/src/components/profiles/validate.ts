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
