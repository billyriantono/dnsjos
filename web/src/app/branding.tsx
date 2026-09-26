import { useEffect } from 'react'

import { useBranding as useBrandingQuery } from '@/lib/api/client'
import type { Branding } from '@/lib/api/types'
import { cn } from '@/lib/utils'

// Runtime branding (GET /api/v1/branding). Every asset is optional: without any the UI falls
// back to the neutral "DnsJos" text mark and /favicon.svg, so the repo never ships brand art.
const NEUTRAL: Branding = {
  name: 'DnsJos',
  tagline: 'dnsdist fleet control panel',
  assets: {
    login_logo: null,
    navbar_light: null,
    navbar_dark: null,
    login_bg: null,
    login_bg_mobile: null,
    cloud: null,
    favicon_ico: null,
    icon_192: null,
    icon_512: null,
    apple_touch: null,
  },
}

// eslint-disable-next-line react-refresh/only-export-components
export function useBranding(): Branding {
  const { data } = useBrandingQuery()
  return {
    name: data?.name || NEUTRAL.name,
    tagline: data?.tagline ?? NEUTRAL.tagline,
    assets: { ...NEUTRAL.assets, ...data?.assets },
  }
}

/** Upserts a <link rel=…> in <head>; removes it when href is null. */
function setLink(rel: string, href: string | null) {
  let el = document.head.querySelector<HTMLLinkElement>(`link[rel="${rel}"]`)
  if (!href) return el?.remove()
  if (!el) document.head.append((el = Object.assign(document.createElement('link'), { rel })))
  el.href = href
}

/** Keeps document.title and the apple-touch-icon in step with the branding. */
export function BrandHead({ title }: { title?: string }) {
  const { name, assets } = useBranding()
  useEffect(() => {
    document.title = title ? `${title} · ${name}` : name
  }, [title, name])
  useEffect(() => {
    setLink('apple-touch-icon', assets.apple_touch)
  }, [assets.apple_touch])
  return null
}

/** Square app icon: the brand icon, else the neutral default. */
export function BrandIcon({ className }: { className?: string }) {
  const { assets } = useBranding()
  return <img src={assets.icon_192 ?? '/favicon.svg'} alt="" className={cn('size-8 shrink-0 rounded-lg', className)} />
}

/** Decorative cloud ornament (only when the brand ships one). */
export function Cloud({ className }: { className?: string }) {
  const { assets } = useBranding()
  if (!assets.cloud) return null
  return (
    <img src={assets.cloud} alt="" aria-hidden draggable={false} className={cn('pointer-events-none absolute select-none', className)} />
  )
}
