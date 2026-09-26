import { useState, type FormEvent } from 'react'
import { LuKeyRound, LuLogOut } from 'react-icons/lu'
import { useNavigate } from 'react-router'
import { toast } from 'sonner'

import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useChangePassword, useLogout } from '@/lib/api/client'
import { cn } from '@/lib/utils'
import { useAuth } from './auth'

export function UserMenu({ className }: { className?: string }) {
  const { user } = useAuth()
  const logout = useLogout()
  const navigate = useNavigate()
  const [pwOpen, setPwOpen] = useState(false)
  if (!user) return null
  const initials = (user.name || user.email).slice(0, 2).toUpperCase()

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon" className={cn('rounded-full', className)} aria-label="Account">
            <Avatar className="size-8">
              <AvatarFallback className="bg-brand-gold text-xs font-semibold text-sidebar-primary-foreground">{initials}</AvatarFallback>
            </Avatar>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56">
          <DropdownMenuLabel className="font-normal">
            <div className="truncate text-sm font-medium">{user.name || user.email}</div>
            <div className="truncate text-xs text-muted-foreground">
              {user.email} · {user.role}
            </div>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => setPwOpen(true)}>
            <LuKeyRound /> Change password
          </DropdownMenuItem>
          <DropdownMenuItem
            onSelect={() => logout.mutate(undefined, { onSettled: () => navigate('/login', { replace: true }) })}
          >
            <LuLogOut /> Sign out
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <ChangePasswordDialog open={pwOpen} onOpenChange={setPwOpen} />
    </>
  )
}

function ChangePasswordDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const change = useChangePassword()
  const [error, setError] = useState('')

  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const f = new FormData(e.currentTarget)
    const current = String(f.get('current'))
    const next = String(f.get('next'))
    if (next.length < 8) return setError('New password must be at least 8 characters.')
    if (next !== f.get('confirm')) return setError('Passwords do not match.')
    setError('')
    change.mutate(
      { current, new: next },
      {
        onSuccess: () => {
          toast.success('Password changed')
          onOpenChange(false)
        },
        onError: (err) => setError(err.message),
      },
    )
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        setError('')
        onOpenChange(o)
      }}
    >
      <DialogContent className="sm:max-w-sm">
        <form onSubmit={submit} className="grid gap-4">
          <DialogHeader>
            <DialogTitle>Change password</DialogTitle>
            <DialogDescription>Use at least 8 characters.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-2">
            <Label htmlFor="pw-current">Current password</Label>
            <Input id="pw-current" name="current" type="password" autoComplete="current-password" required />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="pw-next">New password</Label>
            <Input id="pw-next" name="next" type="password" autoComplete="new-password" minLength={8} required />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="pw-confirm">Confirm new password</Label>
            <Input id="pw-confirm" name="confirm" type="password" autoComplete="new-password" required />
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
          <DialogFooter>
            <Button type="submit" disabled={change.isPending}>
              {change.isPending ? 'Saving…' : 'Change password'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
