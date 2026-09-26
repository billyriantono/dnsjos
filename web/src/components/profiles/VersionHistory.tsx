import { LuGitCompareArrows, LuHistory, LuRocket, LuUndo2 } from 'react-icons/lu'
import { toast } from 'sonner'

import { RequireAdmin } from '@/app/auth'
import { ConfirmDialog } from '@/components/ConfirmDialog'
import { EmptyState } from '@/components/EmptyState'
import { TimeAgo } from '@/components/TimeAgo'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useCreateVersion, usePublishVersion } from '@/lib/api/client'
import type { ConfigVersion } from '@/lib/api/types'
import { cn } from '@/lib/utils'
import { needsRollForward, rollbackComment } from '@/lib/versions'

export function VersionHistory({
  profileId,
  versions,
  loading,
  liveVersion,
  editingVersion,
  nodeCount,
  onLoad,
  onCompare,
}: {
  profileId: string
  versions: ConfigVersion[] | undefined
  loading: boolean
  /** Newest published version — what the profile's nodes run. */
  liveVersion: number | null
  /** Version the editor was loaded from. */
  editingVersion: number | null
  nodeCount: number
  onLoad: (v: ConfigVersion) => void
  onCompare: (a: number, b: number) => void
}) {
  const publish = usePublishVersion()
  const create = useCreateVersion()
  const doPublish = async (v: ConfigVersion) => {
    try {
      let target = v.version
      if (liveVersion !== null && needsRollForward(v.version, liveVersion)) {
        target = (await create.mutateAsync({ id: profileId, spec: v.spec, comment: rollbackComment(v.version, liveVersion) })).version
      }
      await publish.mutateAsync({ id: profileId, version: target })
      toast.success(target === v.version ? `v${v.version} published` : `v${v.version} republished as v${target}`, {
        description: `${nodeCount} node(s) will pick it up on their next poll.`,
      })
    } catch (e) {
      toast.error(`Publish failed: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  return (
    <Card className="gap-3">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <LuHistory className="size-4" /> Version history
        </CardTitle>
        <CardDescription>Saving creates a draft; nodes only get published versions.</CardDescription>
      </CardHeader>
      <CardContent className="px-0">
        {loading && !versions ? (
          <div className="grid gap-2 px-6">
            {Array.from({ length: 4 }, (_, i) => (
              <Skeleton key={i} className="h-14 w-full" />
            ))}
          </div>
        ) : !versions?.length ? (
          <EmptyState icon={LuHistory} title="No versions yet" description="Save the form to create the first draft." />
        ) : (
          <ol className="max-h-[70svh] divide-y overflow-y-auto border-y">
            {versions.map((v, i) => {
              const live = v.version === liveVersion
              const prev = versions[i + 1]
              return (
                <li key={v.id} className={cn('grid gap-1.5 px-6 py-3', v.version === editingVersion && 'bg-muted/40')}>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-semibold">v{v.version}</span>
                    {live ? (
                      <Badge variant="outline" className="border-success/30 bg-success/15 text-success">live</Badge>
                    ) : v.published ? (
                      <Badge variant="secondary">published</Badge>
                    ) : (
                      <Badge variant="outline">draft</Badge>
                    )}
                    {v.version === editingVersion && <span className="text-xs text-muted-foreground">in editor</span>}
                    <TimeAgo date={v.created_at} className="ml-auto text-xs text-muted-foreground" />
                  </div>
                  <p className={cn('text-sm', !v.comment && 'text-muted-foreground italic')}>{v.comment || 'no comment'}</p>
                  <div className="-ml-2 flex flex-wrap gap-1">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" aria-label={`Load v${v.version}`} onClick={() => onLoad(v)}>
                          <LuUndo2 /> Load
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>Load this version into the editor</TooltipContent>
                    </Tooltip>
                    {versions.length > 1 && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 px-2 text-xs"
                        aria-label={prev ? `Diff v${prev.version} to v${v.version}` : `Diff v${v.version} to v${versions[0].version}`}
                        onClick={() => (prev ? onCompare(prev.version, v.version) : onCompare(v.version, versions[0].version))}
                      >
                        <LuGitCompareArrows /> Diff
                      </Button>
                    )}
                    {!live && (
                      <RequireAdmin>
                        <ConfirmDialog
                          title={`Publish v${v.version}?`}
                          description={
                            <>
                              {nodeCount > 0
                                ? `${nodeCount} node(s) on this profile will apply it on their next poll. `
                                : 'No nodes use this profile yet. '}
                              {liveVersion !== null &&
                                needsRollForward(v.version, liveVersion) &&
                                `This rolls back from v${liveVersion} by publishing a copy of v${v.version} as a new version. `}
                              A node that fails to load the config rolls back and reports the error.
                            </>
                          }
                          confirmLabel="Publish"
                          onConfirm={() => doPublish(v)}
                        >
                          <Button variant="ghost" size="sm" className="h-7 px-2 text-xs text-primary">
                            <LuRocket /> Publish
                          </Button>
                        </ConfirmDialog>
                      </RequireAdmin>
                    )}
                  </div>
                </li>
              )
            })}
          </ol>
        )}
      </CardContent>
    </Card>
  )
}
