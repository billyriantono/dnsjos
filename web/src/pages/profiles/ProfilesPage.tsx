import { useState } from 'react'
import { LuLayers, LuPencil, LuPlus, LuTrash2 } from 'react-icons/lu'
import { Link, useNavigate } from 'react-router'
import { toast } from 'sonner'

import { RequireAdmin } from '@/app/auth'
import { ConfirmDialog } from '@/components/ConfirmDialog'
import { DataTable, type Column } from '@/components/DataTable'
import { EmptyState } from '@/components/EmptyState'
import { PageHeader } from '@/components/PageHeader'
import { ProfileDialog } from '@/components/profiles/ProfileDialog'
import { nodesUsing, ProfileNodes } from '@/components/profiles/ProfileNodes'
import { TimeAgo } from '@/components/TimeAgo'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ApiError, useDeleteProfile, useNodes, useProfiles } from '@/lib/api/client'
import type { Profile } from '@/lib/api/types'

export default function ProfilesPage() {
  const navigate = useNavigate()
  const profiles = useProfiles()
  const nodes = useNodes()
  const del = useDeleteProfile()
  const [dialog, setDialog] = useState<{ profile?: Profile } | null>(null)

  const nodesOf = (p: Profile) => nodesUsing(p, nodes.data?.items)

  const remove = (p: Profile) =>
    del.mutateAsync(p.id).then(
      () => toast.success(`Profile "${p.name}" deleted`),
      (e: Error) => {
        if (e instanceof ApiError && e.status === 409) {
          const names = nodesOf(p)?.map((n) => n.name) ?? []
          toast.error(`"${p.name}" is still in use`, {
            description: names.length
              ? `Move these nodes to another profile first: ${names.join(', ')}`
              : 'Move its nodes (and pending enrollment tokens) to another profile first.',
          })
        } else toast.error(`Delete failed: ${e.message}`)
      },
    )

  const columns: Column<Profile>[] = [
    {
      key: 'name',
      header: 'Profile',
      sortValue: (p) => p.name,
      cell: (p) => (
        <div className="grid gap-0.5">
          <Link to={`/profiles/${p.id}`} className="font-medium hover:underline" onClick={(e) => e.stopPropagation()}>
            {p.name}
          </Link>
          {p.description && <span className="line-clamp-1 text-xs text-muted-foreground">{p.description}</span>}
        </div>
      ),
    },
    {
      key: 'published',
      header: 'Live version',
      sortValue: (p) => p.published_version ?? -1,
      cell: (p) =>
        p.published_version === null ? (
          <Badge variant="outline" className="text-muted-foreground">unpublished</Badge>
        ) : (
          <Badge variant="outline" className="border-success/30 bg-success/15 font-mono text-success">v{p.published_version}</Badge>
        ),
    },
    {
      key: 'latest',
      header: 'Latest',
      sortValue: (p) => p.latest_version,
      cell: (p) => (
        <span className="inline-flex items-center gap-2 font-mono text-sm">
          {p.latest_version ? `v${p.latest_version}` : '—'}
          {p.latest_version > (p.published_version ?? 0) && (
            <Badge variant="outline" className="border-warning/30 bg-warning/15 font-sans text-warning">draft ahead</Badge>
          )}
        </span>
      ),
    },
    {
      key: 'nodes',
      header: 'Used by',
      sortValue: (p) => nodesOf(p)?.length ?? p.nodes,
      cell: (p) => <ProfileNodes profile={p} all={nodes.data?.items} />,
    },
    { key: 'created', header: 'Created', sortValue: (p) => p.created_at, cell: (p) => <TimeAgo date={p.created_at} className="text-sm text-muted-foreground" /> },
    {
      key: 'actions',
      header: '',
      align: 'right',
      cell: (p) => (
        <RequireAdmin>
          <div className="flex justify-end gap-1" onClick={(e) => e.stopPropagation()}>
            <Button variant="ghost" size="icon" className="size-8" aria-label={`Rename ${p.name}`} onClick={() => setDialog({ profile: p })}>
              <LuPencil />
            </Button>
            <ConfirmDialog
              title={`Delete profile "${p.name}"?`}
              description={
                (nodesOf(p)?.length ?? p.nodes) > 0
                  ? `${nodesOf(p)?.length ?? p.nodes} node(s) still use it, so the panel will refuse. Move them to another profile first.`
                  : 'All its versions are deleted too. This cannot be undone.'
              }
              confirmLabel="Delete"
              destructive
              onConfirm={() => remove(p)}
            >
              <Button variant="ghost" size="icon" className="size-8 text-muted-foreground hover:text-destructive" aria-label={`Delete ${p.name}`}>
                <LuTrash2 />
              </Button>
            </ConfirmDialog>
          </div>
        </RequireAdmin>
      ),
    },
  ]

  return (
    <>
      <PageHeader
        title="Profiles"
        description="Reusable desired configuration for nodes. Edit, save a draft, then publish it to every node on the profile."
        actions={
          <RequireAdmin>
            <Button onClick={() => setDialog({})}>
              <LuPlus /> New profile
            </Button>
          </RequireAdmin>
        }
      />
      {profiles.isError ? (
        <EmptyState title="Could not load profiles" description={profiles.error.message} />
      ) : (
        <DataTable
          columns={columns}
          rows={profiles.data?.items}
          rowKey={(p) => p.id}
          loading={profiles.isPending}
          defaultSort={{ key: 'name' }}
          onRowClick={(p) => navigate(`/profiles/${p.id}`)}
          empty={
            <EmptyState
              icon={LuLayers}
              title="No profiles yet"
              description="Create a profile to describe listeners, upstreams, blocking and abuse settings for a group of nodes."
              action={
                <RequireAdmin>
                  <Button size="sm" onClick={() => setDialog({})}>
                    <LuPlus /> New profile
                  </Button>
                </RequireAdmin>
              }
            />
          }
        />
      )}
      <ProfileDialog
        key={dialog?.profile?.id ?? 'new'}
        open={dialog !== null}
        onOpenChange={(o) => !o && setDialog(null)}
        profile={dialog?.profile}
        onCreated={(p) => navigate(`/profiles/${p.id}`)}
      />
    </>
  )
}
