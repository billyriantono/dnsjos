import * as React from "react"

const MOBILE_BREAKPOINT = 768
const query = `(max-width: ${MOBILE_BREAKPOINT - 1}px)`

const subscribe = (cb: () => void) => {
  const mql = window.matchMedia(query)
  mql.addEventListener("change", cb)
  return () => mql.removeEventListener("change", cb)
}

export function useIsMobile() {
  return React.useSyncExternalStore(subscribe, () => window.matchMedia(query).matches)
}
