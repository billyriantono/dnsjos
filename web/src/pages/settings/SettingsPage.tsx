import { useState, type FormEvent } from 'react'
import { LuSave, LuUndo2 } from 'react-icons/lu'
import { toast } from 'sonner'

import { RequireAdmin, useAuth } from '@/app/auth'
import { EmptyState } from '@/components/EmptyState'
import { Field } from '@/components/ops/Field'
import { toastError } from '@/components/ops/toast'
import { PageHeader } from '@/components/PageHeader'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { useSettings, useUpdateSettings } from '@/lib/api/client'
import type { Settings } from '@/lib/api/types'
import { fmtDuration } from '@/lib/format'
import { SETTINGS_BOUNDS } from '@/lib/settingsBounds'

import { APITokensCard } from './APITokens'

type NumKey = Exclude<keyof Settings, 'public_url'>

const sections: { title: string; description: string; fields: { key: NumKey; label: string; unit: string; min: number; max: number; hint: (v: number) => string }[] }[] = [
  {
    title: 'Blocklist',
    description: 'How often and how the panel re-fetches sources and rebuilds the CDB.',
    fields: [
      {
        key: 'blocklist_build_interval_minutes',
        label: 'Build interval',
        unit: 'minutes',
        ...SETTINGS_BOUNDS.blocklist_build_interval_minutes,
        hint: (v) => `Every ${fmtDuration(v * 60)}. Unchanged sources produce a skipped build.`,
      },
      {
        key: 'blocklist_download_segments',
        label: 'Blocklist download segments',
        unit: 'streams',
        ...SETTINGS_BOUNDS.blocklist_download_segments,
        hint: () => 'Parallel byte-range download from Komdigi; 1 = single stream.',
      },
    ],
  },
  {
    title: 'Retention',
    description: 'Older data is deleted by the nightly retention job.',
    fields: [
      { key: 'metrics_retention_days', label: 'Metrics', unit: 'days', ...SETTINGS_BOUNDS.metrics_retention_days, hint: () => 'Per-minute node metrics.' },
      {
        key: 'blocked_retention_days',
        label: 'Blocked domains',
        unit: 'days',
        ...SETTINGS_BOUNDS.blocked_retention_days,
        hint: () => 'Daily blocked-domain counts used by Reports. Keep > 365 for the yearly report.',
      },
      {
        key: 'analytics_retention_days',
        label: 'Analytics',
        unit: 'days',
        ...SETTINGS_BOUNDS.analytics_retention_days,
        hint: () => 'Query analytics. Agent batches older than this are dropped.',
      },
    ],
  },
  {
    title: 'Agents',
    description: 'Sent to every agent with its config; changes apply on the next poll.',
    fields: [
      { key: 'agent_poll_interval_s', label: 'Config poll interval', unit: 'seconds', ...SETTINGS_BOUNDS.agent_poll_interval_s, hint: () => 'How often agents check for a new config version.' },
      {
        key: 'agent_heartbeat_interval_s',
        label: 'Heartbeat interval',
        unit: 'seconds',
        ...SETTINGS_BOUNDS.agent_heartbeat_interval_s,
        hint: (v) => `A node is marked offline after ${fmtDuration(v * 3)} without a heartbeat.`,
      },
    ],
  },
]

export default function SettingsPage() {
  const { data, error } = useSettings()
  return (
    <>
      <PageHeader title="Settings" description="Panel-wide settings." />
      {data ? (
        <SettingsForm key={JSON.stringify(data)} initial={data} />
      ) : error ? (
        <EmptyState title="Could not load settings" description={error.message} />
      ) : (
        <Skeleton className="h-96 w-full" />
      )}
      <RequireAdmin>
        <div className="mt-4">
          <APITokensCard />
        </div>
      </RequireAdmin>
    </>
  )
}

function SettingsForm({ initial }: { initial: Settings }) {
  const [s, setS] = useState(initial)
  const save = useUpdateSettings()
  const { isAdmin } = useAuth()
  const dirty = JSON.stringify(s) !== JSON.stringify(initial)
  const submit = (e: FormEvent) => {
    e.preventDefault()
    save.mutate({ ...s, public_url: s.public_url.trim() }, { onSuccess: () => toast.success('Settings saved'), onError: toastError })
  }
  return (
    <form onSubmit={submit} className="space-y-4">
      <fieldset disabled={!isAdmin} className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {sections.map((sec) => (
          <Card key={sec.title}>
            <CardHeader>
              <CardTitle>{sec.title}</CardTitle>
              <CardDescription>{sec.description}</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2">
              {sec.fields.map((f) => (
                <Field key={f.key} id={f.key} label={f.label} hint={f.hint(s[f.key])}>
                  <div className="flex items-center gap-2">
                    <Input
                      id={f.key}
                      type="number"
                      required
                      min={f.min}
                      max={f.max}
                      step={1}
                      className="tabular w-32"
                      value={Number.isNaN(s[f.key]) ? '' : s[f.key]}
                      onChange={(e) => setS({ ...s, [f.key]: e.target.valueAsNumber })}
                    />
                    <span className="text-sm text-muted-foreground">{f.unit}</span>
                  </div>
                </Field>
              ))}
            </CardContent>
          </Card>
        ))}
        <Card>
          <CardHeader>
            <CardTitle>Public URL</CardTitle>
            <CardDescription>Used in the one-line install command shown when adding a node.</CardDescription>
          </CardHeader>
          <CardContent>
            <Field id="public_url" label="URL" hint="Leave empty to use DNSJOS_PUBLIC_URL from the environment.">
              <Input
                id="public_url"
                type="url"
                placeholder="https://dns-panel.example.net"
                value={s.public_url}
                onChange={(e) => setS({ ...s, public_url: e.target.value })}
              />
            </Field>
          </CardContent>
        </Card>
      </fieldset>
      <RequireAdmin>
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" disabled={!dirty || save.isPending} onClick={() => setS(initial)}>
            <LuUndo2 />
            Reset
          </Button>
          <Button type="submit" disabled={!dirty || save.isPending}>
            <LuSave />
            {save.isPending ? 'Saving…' : 'Save settings'}
          </Button>
        </div>
      </RequireAdmin>
    </form>
  )
}
