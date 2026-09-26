import { useState, type FormEvent } from 'react'
import { LuLoaderCircle, LuShieldCheck } from 'react-icons/lu'
import { Navigate, useNavigate, useSearchParams } from 'react-router'

import { useAuth } from '@/app/auth'
import { ThemeToggle } from '@/app/theme-toggle'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
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

  return (
    <main className="relative flex min-h-svh items-center justify-center bg-muted/30 p-4">
      <div className="absolute top-4 right-4">
        <ThemeToggle />
      </div>
      <div className="w-full max-w-sm space-y-6">
        <div className="flex flex-col items-center gap-2 text-center">
          <span className="flex size-11 items-center justify-center rounded-xl bg-primary text-primary-foreground shadow-sm">
            <LuShieldCheck className="size-6" />
          </span>
          <h1 className="text-xl font-semibold tracking-tight">DnsJos</h1>
          <p className="text-sm text-muted-foreground">dnsdist fleet control panel</p>
        </div>
        <Card>
          <CardHeader>
            <CardTitle>Sign in</CardTitle>
            <CardDescription>Use your panel account.</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={submit} className="grid gap-4">
              <div className="grid gap-2">
                <Label htmlFor="email">Email</Label>
                <Input id="email" name="email" type="email" autoComplete="username" autoFocus required />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="password">Password</Label>
                <Input id="password" name="password" type="password" autoComplete="current-password" required />
              </div>
              {error && (
                <p role="alert" className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                  {error}
                </p>
              )}
              <Button type="submit" disabled={login.isPending} className="w-full">
                {login.isPending && <LuLoaderCircle className="animate-spin" />}
                Sign in
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </main>
  )
}
