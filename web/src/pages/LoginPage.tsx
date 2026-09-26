import { useState, type FormEvent } from 'react'
import { LuEye, LuEyeOff, LuLoaderCircle, LuLock, LuMail } from 'react-icons/lu'
import { Navigate, useNavigate, useSearchParams } from 'react-router'

import { useAuth } from '@/app/auth'
import { BrandHead, BrandIcon, Cloud, useBranding } from '@/app/branding'
import { ThemeToggle } from '@/app/theme-toggle'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ApiError, useLogin } from '@/lib/api/client'

/** Only same-origin paths, so ?next= cannot be used as an open redirect. */
function safeNext(next: string | null) {
  return next && next.startsWith('/') && !next.startsWith('//') ? next : '/'
}

export default function LoginPage() {
  const { user } = useAuth()
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const login = useLogin()
  const [error, setError] = useState('')
  const [showPw, setShowPw] = useState(false)
  const { name, tagline, assets } = useBranding()
  const next = safeNext(params.get('next'))

  if (user) return <Navigate to={next} replace />

  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const f = new FormData(e.currentTarget)
    setError('')
    login.mutate(
      { email: String(f.get('email')).trim(), password: String(f.get('password')) },
      {
        onSuccess: () => navigate(next, { replace: true }),
        onError: (err) =>
          setError(
            err instanceof ApiError && err.status === 401
              ? 'Invalid email or password.'
              : err instanceof ApiError && err.status === 429
                ? 'Too many attempts. Wait a minute and try again.'
                : err.message || 'Sign-in failed.',
          ),
      },
    )
  }

  const invalid = error !== '' || undefined
  return (
    <main className="relative isolate flex min-h-svh items-center justify-center overflow-hidden bg-brand-navy p-4 md:justify-start md:pl-[8vw]">
      <BrandHead />
      {assets.login_bg ? (
        <picture className="absolute inset-0 -z-10">
          {assets.login_bg_mobile && <Sources url={assets.login_bg_mobile} media="(max-width: 767px)" />}
          <Sources url={assets.login_bg} />
          <img
            src={jpg(assets.login_bg)}
            alt=""
            className="size-full object-cover object-center md:object-[72%_50%]"
          />
        </picture>
      ) : (
        <div
          aria-hidden
          className="absolute inset-0 -z-10 bg-[radial-gradient(ellipse_at_80%_20%,oklch(0.45_0.14_258),transparent_60%),radial-gradient(ellipse_at_10%_100%,oklch(0.35_0.1_240),transparent_55%)]"
        />
      )}
      {/* Mobile: soften the portrait artwork behind the centred card. */}
      <div aria-hidden className="absolute inset-0 -z-10 bg-brand-navy/35 backdrop-blur-[2px] md:hidden" />
      <div className="absolute top-4 right-4">
        <ThemeToggle className="text-white hover:bg-white/15 hover:text-white dark:hover:bg-white/15" />
      </div>

      <div className="relative w-full max-w-sm">
        <Cloud className="-right-24 -bottom-14 w-80 opacity-70" />
        <section className="relative rounded-2xl bg-card px-7 py-8 text-card-foreground shadow-2xl ring-1 shadow-black/40 ring-black/5 dark:bg-[oklch(0.2_0.03_262)] dark:ring-white/10">
          <header className="mb-6 flex flex-col items-center gap-2 text-center">
            {assets.login_logo ? (
              <div className="relative">
                {/* Light halo so a logo with dark lettering reads on the dark card too. */}
                <div
                  aria-hidden
                  className="absolute -inset-x-6 -inset-y-2 hidden rounded-full bg-[radial-gradient(closest-side,rgb(255_255_255/0.9)_30%,rgb(255_255_255/0.35)_65%,transparent)] blur-md dark:block"
                />
                <img src={assets.login_logo} alt="" className="relative h-36 w-auto" />
              </div>
            ) : (
              <BrandIcon className="size-12 rounded-xl shadow-sm" />
            )}
            <h1 className={assets.login_logo ? 'sr-only' : 'text-2xl font-semibold tracking-tight'}>{name}</h1>
            {tagline && <p className="text-sm text-balance text-muted-foreground">{tagline}</p>}
          </header>

          <form onSubmit={submit} className="grid gap-4">
            <div className="grid gap-2">
              <Label htmlFor="email">Email</Label>
              <div className="relative">
                <LuMail aria-hidden className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="email"
                  name="email"
                  type="email"
                  autoComplete="username"
                  placeholder="you@example.com"
                  autoFocus
                  required
                  aria-invalid={invalid}
                  aria-describedby={error ? 'login-error' : undefined}
                  className="h-10 pl-9"
                />
              </div>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="password">Password</Label>
              <div className="relative">
                <LuLock aria-hidden className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="password"
                  name="password"
                  type={showPw ? 'text' : 'password'}
                  autoComplete="current-password"
                  required
                  aria-invalid={invalid}
                  aria-describedby={error ? 'login-error' : undefined}
                  className="h-10 pr-10 pl-9"
                />
                <button
                  type="button"
                  onClick={() => setShowPw((v) => !v)}
                  aria-label={showPw ? 'Hide password' : 'Show password'}
                  aria-pressed={showPw}
                  className="absolute top-1/2 right-1 flex size-8 -translate-y-1/2 items-center justify-center rounded-md text-muted-foreground outline-none hover:text-foreground focus-visible:ring-[3px] focus-visible:ring-ring/50"
                >
                  {showPw ? <LuEyeOff className="size-4" /> : <LuEye className="size-4" />}
                </button>
              </div>
            </div>
            {error && (
              <p
                id="login-error"
                role="alert"
                className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive"
              >
                {error}
              </p>
            )}
            <Button type="submit" size="lg" disabled={login.isPending} className="mt-1 w-full">
              {login.isPending && <LuLoaderCircle className="animate-spin" />}
              {login.isPending ? 'Signing in…' : 'Sign in'}
            </Button>
          </form>
        </section>
      </div>
    </main>
  )
}

/** The panel prefers login-bg.webp; browsers without WebP fall back to its .jpg sibling. */
const jpg = (url: string) => url.replace(/\.webp(?=\?|$)/, '.jpg')

function Sources({ url, media }: { url: string; media?: string }) {
  return (
    <>
      {/\.webp(\?|$)/.test(url) && <source type="image/webp" srcSet={url} media={media} />}
      <source srcSet={jpg(url)} media={media} />
    </>
  )
}
