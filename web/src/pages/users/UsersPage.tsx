import { useState, type FormEvent, type ReactNode } from 'react'
import { LuKeyRound, LuPencil, LuPlus, LuTrash2, LuUsers } from 'react-icons/lu'
import { toast } from 'sonner'

import { useAuth } from '@/app/auth'
import { AdminOnly } from '@/components/AdminOnly'
import { ConfirmDialog } from '@/components/ConfirmDialog'
import { DataTable, type Column } from '@/components/DataTable'
import { EmptyState } from '@/components/EmptyState'
import { Field } from '@/components/ops/Field'
import { toastError } from '@/components/ops/toast'
import { PageHeader } from '@/components/PageHeader'
import { TimeAgo } from '@/components/TimeAgo'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { useCreateUser, useDeleteUser, useUpdateUser, useUsers } from '@/lib/api/client'
import type { Role, User } from '@/lib/api/types'

const MIN_PASSWORD = 8

type Editing = { mode: 'create' } | { mode: 'edit' | 'password'; user: User }

export default function UsersPage() {
  return (
    <AdminOnly title="Users">
      <Users />
    </AdminOnly>
  )
}

function Users() {
  const { user: me } = useAuth()
  const { data, isPending, error } = useUsers()
  const update = useUpdateUser()
  const remove = useDeleteUser()
  const [editing, setEditing] = useState<Editing | null>(null)

  const columns: Column<User>[] = [
    {
      key: 'user',
      header: 'User',
      sortValue: (u) => u.email,
      cell: (u) => (
        <div>
          <div className="font-medium">
            {u.name || u.email}
            {u.id === me?.id && <span className="ml-1.5 text-xs text-muted-foreground">(you)</span>}
          </div>
          {u.name && <div className="text-xs text-muted-foreground">{u.email}</div>}
        </div>
      ),
    },
    {
      key: 'role',
      header: 'Role',
      sortValue: (u) => u.role,
      cell: (u) => <Badge variant={u.role === 'admin' ? 'default' : 'secondary'}>{u.role}</Badge>,
    },
    {
      key: 'active',
      header: 'Active',
      sortValue: (u) => !u.disabled,
      cell: (u) => (
        <Switch
          checked={!u.disabled}
          disabled={u.id === me?.id || update.isPending}
          aria-label={`${u.email} active`}
          onCheckedChange={(on) =>
            update.mutate(
              { id: u.id, patch: { disabled: !on } },
              { onSuccess: () => toast.success(`${u.email} ${on ? 'enabled' : 'disabled'}`), onError: toastError },
            )
          }
        />
      ),
    },
    { key: 'login', header: 'Last login', sortValue: (u) => u.last_login_at, cell: (u) => <TimeAgo date={u.last_login_at} /> },
    { key: 'created', header: 'Created', sortValue: (u) => u.created_at, cell: (u) => <TimeAgo date={u.created_at} /> },
    {
      key: 'actions',
      header: '',
      align: 'right',
      cell: (u) => (
        <div className="flex justify-end gap-1">
          <Button variant="ghost" size="icon" className="size-8" aria-label="Edit" onClick={() => setEditing({ mode: 'edit', user: u })}>
            <LuPencil />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="size-8"
            aria-label="Reset password"
            // PATCHing a password ends every session of that user, including this one; use Change password in the account menu instead.
            disabled={u.id === me?.id}
            title={u.id === me?.id ? 'Use Change password in the account menu' : undefined}
            onClick={() => setEditing({ mode: 'password', user: u })}
          >
            <LuKeyRound />
          </Button>
          <ConfirmDialog
            title={`Delete ${u.email}?`}
            description="Their sessions end immediately. Audit entries keep their email."
            confirmLabel="Delete"
            destructive
            onConfirm={() => remove.mutateAsync(u.id).then(() => toast.success(`${u.email} deleted`), toastError)}
          >
            <Button variant="ghost" size="icon" className="size-8 text-destructive" aria-label="Delete" disabled={u.id === me?.id}>
              <LuTrash2 />
            </Button>
          </ConfirmDialog>
        </div>
      ),
    },
  ]

  return (
    <>
      <PageHeader
        title="Users"
        description="Admins can change everything; viewers are read-only."
        actions={
          <Button onClick={() => setEditing({ mode: 'create' })}>
            <LuPlus />
            Add user
          </Button>
        }
      />
      <DataTable
        columns={columns}
        rows={data?.items}
        loading={isPending}
        rowKey={(u) => u.id}
        defaultSort={{ key: 'user' }}
        empty={error ? <EmptyState title="Could not load users" description={error.message} /> : <EmptyState icon={LuUsers} title="No users" />}
      />
      {editing?.mode === 'create' && <CreateDialog onClose={() => setEditing(null)} />}
      {editing?.mode === 'edit' && <EditDialog user={editing.user} self={editing.user.id === me?.id} onClose={() => setEditing(null)} />}
      {editing?.mode === 'password' && <PasswordDialog user={editing.user} onClose={() => setEditing(null)} />}
    </>
  )
}

function RoleSelect({ id, value, onChange, disabled }: { id: string; value: Role; onChange: (r: Role) => void; disabled?: boolean }) {
  return (
    <Select value={value} onValueChange={(v) => onChange(v as Role)} disabled={disabled}>
      <SelectTrigger id={id} className="w-full">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="viewer">Viewer — read only</SelectItem>
        <SelectItem value="admin">Admin — full access</SelectItem>
      </SelectContent>
    </Select>
  )
}

function FormDialog({
  title,
  description,
  onClose,
  onSubmit,
  pending,
  submitLabel,
  children,
}: {
  title: string
  description?: string
  onClose: () => void
  onSubmit: () => void
  pending: boolean
  submitLabel: string
  children: ReactNode
}) {
  const submit = (e: FormEvent) => {
    e.preventDefault()
    onSubmit()
  }
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description && <DialogDescription>{description}</DialogDescription>}
        </DialogHeader>
        <form onSubmit={submit} className="grid gap-4">
          {children}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={pending}>
              {submitLabel}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

const done = (msg: string, onClose: () => void) => ({
  onSuccess: () => {
    toast.success(msg)
    onClose()
  },
  onError: toastError,
})

function CreateDialog({ onClose }: { onClose: () => void }) {
  const [f, setF] = useState({ email: '', name: '', password: '', role: 'viewer' as Role })
  const create = useCreateUser()
  return (
    <FormDialog
      title="Add user"
      onClose={onClose}
      pending={create.isPending}
      submitLabel="Create user"
      onSubmit={() => create.mutate({ ...f, email: f.email.trim(), name: f.name.trim() }, done(`${f.email} created`, onClose))}
    >
      <Field id="u-email" label="Email">
        <Input id="u-email" type="email" required value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} />
      </Field>
      <Field id="u-name" label="Name">
        <Input id="u-name" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} />
      </Field>
      <Field id="u-pw" label="Password" hint={`At least ${MIN_PASSWORD} characters.`}>
        <Input
          id="u-pw"
          type="password"
          autoComplete="new-password"
          required
          minLength={MIN_PASSWORD}
          value={f.password}
          onChange={(e) => setF({ ...f, password: e.target.value })}
        />
      </Field>
      <Field id="u-role" label="Role">
        <RoleSelect id="u-role" value={f.role} onChange={(role) => setF({ ...f, role })} />
      </Field>
    </FormDialog>
  )
}

function EditDialog({ user, self, onClose }: { user: User; self: boolean; onClose: () => void }) {
  const [name, setName] = useState(user.name)
  const [role, setRole] = useState(user.role)
  const update = useUpdateUser()
  return (
    <FormDialog
      title={`Edit ${user.email}`}
      onClose={onClose}
      pending={update.isPending}
      submitLabel="Save"
      onSubmit={() => update.mutate({ id: user.id, patch: { name: name.trim(), role } }, done('User saved', onClose))}
    >
      <Field id="e-name" label="Name">
        <Input id="e-name" value={name} onChange={(e) => setName(e.target.value)} />
      </Field>
      <Field id="e-role" label="Role" hint={self ? 'You cannot change your own role.' : undefined}>
        <RoleSelect id="e-role" value={role} onChange={setRole} disabled={self} />
      </Field>
    </FormDialog>
  )
}

function PasswordDialog({ user, onClose }: { user: User; onClose: () => void }) {
  const [pw, setPw] = useState('')
  const update = useUpdateUser()
  return (
    <FormDialog
      title="Reset password"
      description={`Set a new password for ${user.email}.`}
      onClose={onClose}
      pending={update.isPending}
      submitLabel="Reset password"
      onSubmit={() => update.mutate({ id: user.id, patch: { password: pw } }, done('Password reset', onClose))}
    >
      <Field id="p-new" label="New password" hint={`At least ${MIN_PASSWORD} characters.`}>
        <Input
          id="p-new"
          type="password"
          autoComplete="new-password"
          required
          minLength={MIN_PASSWORD}
          value={pw}
          onChange={(e) => setPw(e.target.value)}
        />
      </Field>
    </FormDialog>
  )
}
