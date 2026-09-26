import { useState } from 'react'
import { LuPackageCheck } from 'react-icons/lu'

import { useAuth } from '@/app/auth'
import { DataTable, type Column } from '@/components/DataTable'
import { EmptyState } from '@/components/EmptyState'
import { PageHeader } from '@/components/PageHeader'
import { StatusBadge } from '@/components/StatusBadge'
import { UserName } from '@/components/UserName'
import { TimeAgo } from '@/components/TimeAgo'
import { NewRunDialog } from '@/components/upgrades/NewRunDialog'
import { RunCard } from '@/components/upgrades/RunCard'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useUpgrades } from '@/lib/api/client'
import type { UpgradeRun } from '@/lib/api/types'

// The Run cell is a button so a finished run's timeline can be opened from the keyboard, not just by clicking the row.
const columns = (open: (id: number) => void): Column<UpgradeRun>[] => [
  {
    key: 'id',
    header: 'Run',
    sortValue: (r) => r.id,
    cell: (r) => (
      <button type="button" className="font-medium underline-offset-4 hover:underline" aria-label={`Open run #${r.id}`} onClick={() => open(r.id)}>
        #{r.id}
      </button>
    ),
  },
  { key: 'kind', header: 'Kind', sortValue: (r) => r.kind, cell: (r) => r.kind },
  { key: 'target', header: 'Target', sortValue: (r) => r.target_version, cell: (r) => <span className="font-mono text-xs">{r.target_version || '—'}</span> },
  { key: 'status', header: 'Status', sortValue: (r) => r.status, cell: (r) => <StatusBadge status={r.status} /> },
  {
    key: 'nodes',
    header: 'Nodes',
    align: 'right',
    sortValue: (r) => r.steps.length,
    cell: (r) => `${r.steps.filter((s) => s.status === 'ok').length}/${r.steps.length} ok`,
  },
  { key: 'by', header: 'By', sortValue: (r) => r.created_by, cell: (r) => (r.created_by ? <UserName id={r.created_by} /> : '—') },
  { key: 'created', header: 'Started', sortValue: (r) => r.created_at, cell: (r) => <TimeAgo date={r.created_at} className="text-muted-foreground" /> },
  { key: 'finished', header: 'Finished', sortValue: (r) => r.finished_at, cell: (r) => <TimeAgo date={r.finished_at} className="text-muted-foreground" /> },
]

export default function UpgradesPage() {
  const { isAdmin } = useAuth()
  const runs = useUpgrades()
  const [selected, setSelected] = useState<number>()
  const items = runs.data?.items
  const active = items?.find((r) => r.status === 'running' || r.status === 'paused')
  const shown = selected ?? active?.id

  return (
    <>
      <PageHeader
        title="Upgrades"
        description="Roll dnsdist or the agent across the fleet, one node at a time."
        actions={isAdmin && <NewRunDialog activeRun={!!active} onCreated={setSelected} />}
      />
      {shown != null && <RunCard key={shown} id={shown} />}
      <Card>
        <CardHeader>
          <CardTitle>History</CardTitle>
        </CardHeader>
        <CardContent className="px-0">
          <DataTable
            columns={columns(setSelected)}
            rows={items}
            rowKey={(r) => r.id}
            loading={runs.isPending}
            error={runs.error}
            defaultSort={{ key: 'id', desc: true }}
            onRowClick={(r) => setSelected(r.id)}
            empty={<EmptyState icon={LuPackageCheck} title="No upgrade runs yet" description="Start a rolling upgrade to update dnsdist or the agent across nodes." />}
          />
        </CardContent>
      </Card>
    </>
  )
}
