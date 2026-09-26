import { useState } from 'react'
import { LuCircleCheck, LuPlus } from 'react-icons/lu'
import { toast } from 'sonner'

import { CopyButton } from '@/components/CopyButton'
import { TimeAgo } from '@/components/TimeAgo'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { useCreateEnrollmentToken, useProfiles } from '@/lib/api/client'
import type { EnrollmentTokenCreated, Labels } from '@/lib/api/types'
import { fmtDateTime } from '@/lib/format'

const DEFAULT_PROFILE = '__default'

/** "key=value" per line (or comma separated) → Labels; returns an error string on bad input. */
function parseLabels(text: string): Labels | string {
  const out: Labels = {}
  for (const raw of text.split(/[\n,]/)) {
    const line = raw.trim()
    if (!line) continue
    const i = line.indexOf('=')
    if (i < 1) return `Label "${line}" must look like key=value`
    out[line.slice(0, i).trim()] = line.slice(i + 1).trim()
  }
  return out
}

export function AddNodeDialog() {
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [profile, setProfile] = useState(DEFAULT_PROFILE)
  const [ttl, setTtl] = useState('24')
  const [labels, setLabels] = useState('')
  const [created, setCreated] = useState<EnrollmentTokenCreated>()
  const profiles = useProfiles()
  const create = useCreateEnrollmentToken()

  const reset = (o: boolean) => {
    setOpen(o)
    if (!o) {
      setName('')
      setLabels('')
      setTtl('24')
      setProfile(DEFAULT_PROFILE)
      setCreated(undefined)
      create.reset()
    }
  }

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const parsed = parseLabels(labels)
    if (typeof parsed === 'string') return toast.error(parsed)
    create.mutate(
      { node_name: name.trim(), labels: parsed, profile_id: profile === DEFAULT_PROFILE ? null : profile, ttl_hours: Number(ttl) || 24 },
      {
        onSuccess: (t) => {
          setCreated(t)
          toast.success('Enrollment token created')
        },
        onError: (err) => toast.error(err.message),
      },
    )
  }

  return (
    <Dialog open={open} onOpenChange={reset}>
      <DialogTrigger asChild>
        <Button>
          <LuPlus /> Add node
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-xl">
        {created ? (
          <>
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <LuCircleCheck className="text-success" /> Run this on the new node
              </DialogTitle>
              <DialogDescription>
                As root on a Debian 12/13 or Ubuntu 22.04/24.04 host. The token is shown only once and expires{' '}
                <TimeAgo date={created.expires_at} /> ({fmtDateTime(created.expires_at)}).
              </DialogDescription>
            </DialogHeader>
            <div className="flex items-start gap-2 rounded-md border bg-muted/50 p-3">
              <code className="min-w-0 flex-1 font-mono text-xs break-all">{created.install_command}</code>
              <CopyButton value={created.install_command} />
            </div>
            <div className="space-y-1 text-sm text-muted-foreground">
              <p className="font-medium text-foreground">What happens next</p>
              <ol className="list-decimal space-y-0.5 pl-5">
                <li>The installer adds the PowerDNS repo and installs dnsdist (an existing /etc/dnsdist is backed up).</li>
                <li>It downloads the agent, enrolls with this token and starts dnsjos-agent.</li>
                <li>The agent pulls its config and the blocklist, then the node shows up here as online.</li>
              </ol>
            </div>
            <DialogFooter>
              <Button onClick={() => reset(false)}>Done</Button>
            </DialogFooter>
          </>
        ) : (
          <form onSubmit={submit} className="grid gap-4">
            <DialogHeader>
              <DialogTitle>Add node</DialogTitle>
              <DialogDescription>Creates a single-use enrollment token and a one-line install command.</DialogDescription>
            </DialogHeader>
            <div className="grid gap-2">
              <Label htmlFor="node-name">Node name</Label>
              <Input id="node-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="dns-jkt-1" required autoFocus />
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="grid gap-2">
                <Label htmlFor="enroll-profile">Profile</Label>
                <Select value={profile} onValueChange={setProfile}>
                  <SelectTrigger id="enroll-profile" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={DEFAULT_PROFILE}>Panel default</SelectItem>
                    {profiles.data?.items.map((p) => (
                      <SelectItem key={p.id} value={p.id}>
                        {p.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="node-ttl">Token valid for (hours)</Label>
                <Input id="node-ttl" type="number" min={1} max={720} value={ttl} onChange={(e) => setTtl(e.target.value)} />
              </div>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="node-labels">Labels</Label>
              <Textarea id="node-labels" value={labels} onChange={(e) => setLabels(e.target.value)} placeholder={'site=jkt\nrole=primary'} rows={2} className="font-mono text-xs" />
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => reset(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={create.isPending || !name.trim()}>
                Create token
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}
