import { useState, type FormEvent } from 'react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { useCreateProfile, useProfiles, useUpdateProfile } from '@/lib/api/client'
import type { Profile } from '@/lib/api/types'

const DEFAULTS = 'defaults'

/** Create (no `profile`) or rename/describe an existing profile. */
export function ProfileDialog({
  open,
  onOpenChange,
  profile,
  onCreated,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  profile?: Profile
  onCreated?: (p: Profile) => void
}) {
  const create = useCreateProfile()
  const update = useUpdateProfile()
  const profiles = useProfiles()
  const [error, setError] = useState('')
  const [copyFrom, setCopyFrom] = useState(DEFAULTS)
  const busy = create.isPending || update.isPending

  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const f = new FormData(e.currentTarget)
    const body = { name: String(f.get('name')).trim(), description: String(f.get('description')).trim() }
    if (!body.name) return setError('Name is required.')
    const done = (p: Profile) => {
      toast.success(profile ? `Profile "${p.name}" updated` : `Profile "${p.name}" created`)
      onOpenChange(false)
      if (!profile) onCreated?.(p)
    }
    const fail = (err: Error) => setError(err.message === 'already exists' ? 'A profile with this name already exists.' : err.message)
    if (profile) update.mutate({ id: profile.id, ...body }, { onSuccess: done, onError: fail })
    else create.mutate({ ...body, copy_from: copyFrom === DEFAULTS ? undefined : copyFrom }, { onSuccess: done, onError: fail })
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        setError('')
        setCopyFrom(DEFAULTS)
        onOpenChange(o)
      }}
    >
      <DialogContent className="sm:max-w-md">
        <form onSubmit={submit} className="grid gap-4">
          <DialogHeader>
            <DialogTitle>{profile ? 'Edit profile' : 'New profile'}</DialogTitle>
            <DialogDescription>
              {profile ? 'Rename or re-describe this profile. Its versions are unchanged.' : 'A reusable desired configuration you can assign to nodes.'}
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-2">
            <Label htmlFor="profile-name">Name</Label>
            <Input id="profile-name" name="name" defaultValue={profile?.name} placeholder="jakarta-edge" required autoFocus />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="profile-desc">Description</Label>
            <Textarea id="profile-desc" name="description" defaultValue={profile?.description} placeholder="What these nodes are for" />
          </div>
          {!profile && (
            <div className="grid gap-2">
              <Label htmlFor="profile-copy">Start from</Label>
              <Select value={copyFrom} onValueChange={setCopyFrom}>
                <SelectTrigger id="profile-copy" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={DEFAULTS}>Production defaults</SelectItem>
                  {profiles.data?.items
                    .filter((p) => p.published_version !== null)
                    .map((p) => (
                      <SelectItem key={p.id} value={p.id}>
                        Copy of {p.name} (live v{p.published_version})
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>
            </div>
          )}
          {error && <p className="text-sm text-destructive">{error}</p>}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={busy}>
              {busy ? 'Saving…' : profile ? 'Save' : 'Create'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
