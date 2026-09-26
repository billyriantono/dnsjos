import { useEffect, useState, type FormEvent } from 'react'
import { LuCircleAlert, LuSave, LuUndo2 } from 'react-icons/lu'
import { Link, useBlocker, useParams } from 'react-router'
import { toast } from 'sonner'

import { RequireAdmin, useAuth } from '@/app/auth'
import { EmptyState } from '@/components/EmptyState'
import { PageHeader } from '@/components/PageHeader'
import { ConfigForm } from '@/components/profiles/ConfigForm'
import { ReadOnlyContext, SpecErrorsContext, tabOf, TABS, type TabId } from '@/components/profiles/context'
import { PreviewDialog } from '@/components/profiles/PreviewDialog'
import { nodesUsing, ProfileNodes } from '@/components/profiles/ProfileNodes'
import { VersionDiffDialog } from '@/components/profiles/VersionDiff'
import { VersionHistory } from '@/components/profiles/VersionHistory'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Badge } from '@/components/ui/badge'
import { Button, buttonVariants } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import { ApiError, useCreateVersion, useNodes, useProfile, useProfileVersions } from '@/lib/api/client'
import { defaultSpec, normalizeSpec, parseSpecErrors, type SpecErrors } from '@/lib/api/profiles'
import type { ConfigVersion, Profile } from '@/lib/api/types'

export default function ProfileEditorPage() {
  const { id = '' } = useParams()
  const profile = useProfile(id)
  const versions = useProfileVersions(id)

  if (profile.isError || versions.isError)
    return (
      <EmptyState
        title={profile.error instanceof ApiError && profile.error.status === 404 ? 'Profile not found' : 'Could not load profile'}
        description={(profile.error ?? versions.error)?.message}
        action={
          <Button asChild variant="outline" size="sm">
            <Link to="/profiles">Back to profiles</Link>
          </Button>
        }
      />
    )
  if (!profile.data || !versions.data)
    return (
      <>
        <Skeleton className="h-9 w-64" />
        <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1fr)_18rem]">
          <div className="grid content-start gap-4">
            <Skeleton className="h-9 w-full max-w-2xl" />
            <Skeleton className="h-72 w-full" />
            <Skeleton className="h-48 w-full" />
          </div>
          <Skeleton className="h-96 w-full" />
        </div>
      </>
    )
  // Keyed so the local draft starts over when navigating to another profile.
  return <Editor key={id} profile={profile.data} versions={versions.data.items} latest={versions.data.items[0]} />
}

function Editor({ profile, versions, latest }: { profile: Profile; versions: ConfigVersion[]; latest?: ConfigVersion }) {
  const { isAdmin } = useAuth()
  const nodes = useNodes()
  const create = useCreateVersion()

  const [base, setBase] = useState(() => normalizeSpec(latest?.spec ?? defaultSpec()))
  const [draft, setDraft] = useState(base)
  const [loadedFrom, setLoadedFrom] = useState<number | null>(latest?.version ?? null)
  const [errors, setErrors] = useState<SpecErrors>({})
  const [tab, setTab] = useState<TabId>('listen')
  const [saveOpen, setSaveOpen] = useState(false)
  const [pendingLoad, setPendingLoad] = useState<ConfigVersion | null>(null)
  const [diffPair, setDiffPair] = useState<[number, number] | null>(null)

  const dirty = JSON.stringify(draft) !== JSON.stringify(base)
  const canSave = dirty || versions.length === 0

  const blocker = useBlocker(({ currentLocation, nextLocation }) => dirty && currentLocation.pathname !== nextLocation.pathname)
  useEffect(() => {
    if (!dirty) return
    const warn = (e: BeforeUnloadEvent) => e.preventDefault()
    window.addEventListener('beforeunload', warn)
    return () => window.removeEventListener('beforeunload', warn)
  }, [dirty])

  const showErrors = (e: SpecErrors) => {
    setErrors(e)
    const first = Object.keys(e).map(tabOf).find(Boolean)
    if (first) setTab(first)
  }

  const load = (v: ConfigVersion) => {
    setDraft(normalizeSpec(v.spec))
    setLoadedFrom(v.version)
    setErrors({})
    setPendingLoad(null)
    toast.info(`Loaded v${v.version} into the editor`, { description: 'Save to create a new draft from it.' })
  }
  const discard = () => {
    setDraft(base)
    setLoadedFrom(latest?.version ?? null)
    setErrors({})
  }

  const save = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const comment = String(new FormData(e.currentTarget).get('comment')).trim()
    create.mutate(
      { id: profile.id, spec: draft, comment },
      {
        onSuccess: (v) => {
          const spec = normalizeSpec(v.spec)
          setBase(spec)
          setDraft(spec)
          setLoadedFrom(v.version)
          setErrors({})
          setSaveOpen(false)
          toast.success(`Saved as draft v${v.version}`, { description: 'Publish it from the version history to roll it out.' })
        },
        onError: (err) => {
          setSaveOpen(false)
          if (err instanceof ApiError && err.status < 500) {
            const parsed = parseSpecErrors(err.message)
            showErrors(parsed)
            const n = Object.values(parsed).flat().length
            toast.error(`Not saved: ${n} validation problem${n === 1 ? '' : 's'}`)
          } else toast.error(`Save failed: ${err.message}`)
        },
      },
    )
  }

  const errorList = Object.entries(errors).flatMap(([path, msgs]) => msgs.map((m) => ({ path, m })))

  return (
    <SpecErrorsContext value={errors}>
      <ReadOnlyContext value={!isAdmin}>
        <PageHeader
          title={profile.name}
          description={
            <span className="flex flex-wrap items-center gap-2">
              {profile.description || 'No description'}
              <span className="text-muted-foreground/50">·</span>
              {profile.published_version !== null ? (
                <Badge variant="outline" className="border-success/30 bg-success/15 text-success">live v{profile.published_version}</Badge>
              ) : (
                <Badge variant="outline">unpublished</Badge>
              )}
              {loadedFrom !== null && <span>editing from v{loadedFrom}</span>}
              {dirty && <Badge variant="outline" className="border-warning/30 bg-warning/15 text-warning">unsaved changes</Badge>}
            </span>
          }
          actions={
            <>
              <ProfileNodes profile={profile} all={nodes.data?.items} />
              <PreviewDialog profileId={profile.id} spec={draft} onErrors={showErrors} />
              <RequireAdmin>
                <Button onClick={() => setSaveOpen(true)} disabled={!canSave || create.isPending}>
                  <LuSave /> Save draft
                </Button>
              </RequireAdmin>
            </>
          }
        />

        {!isAdmin && <p className="text-sm text-muted-foreground">Read-only: only admins can change profiles.</p>}
        {versions.length === 0 && (
          <p className="rounded-md border border-dashed p-3 text-sm text-muted-foreground">
            This profile has no versions yet — the form starts from the production defaults. Save it to create v1.
          </p>
        )}

        {errorList.length > 0 && (
          <div className="rounded-lg border border-destructive/40 bg-destructive/5 p-4">
            <p className="mb-2 flex items-center gap-2 text-sm font-medium text-destructive">
              <LuCircleAlert className="size-4" /> {errorList.length} validation problem{errorList.length === 1 ? '' : 's'}
            </p>
            <ul className="grid gap-1 text-sm">
              {errorList.map(({ path, m }, i) => {
                const t = tabOf(path)
                return (
                  <li key={i}>
                    {t ? (
                      <button type="button" className="text-left hover:underline" onClick={() => setTab(t)}>
                        <span className="font-mono text-xs text-muted-foreground">{path}</span> {m}
                        <span className="ml-1 text-xs text-muted-foreground">({TABS.find((x) => x.id === t)?.label})</span>
                      </button>
                    ) : (
                      m
                    )}
                  </li>
                )
              })}
            </ul>
          </div>
        )}

        <div className="grid grid-cols-1 items-start gap-6 xl:grid-cols-[minmax(0,1fr)_18rem]">
          <ConfigForm value={draft} onChange={setDraft} errors={errors} tab={tab} onTabChange={setTab} />
          <div className="xl:sticky xl:top-20">
            <VersionHistory
              profileId={profile.id}
              versions={versions}
              loading={false}
              liveVersion={profile.published_version}
              editingVersion={loadedFrom}
              nodeCount={nodesUsing(profile, nodes.data?.items)?.length ?? profile.nodes}
              onLoad={(v) => (dirty ? setPendingLoad(v) : load(v))}
              onCompare={(a, b) => setDiffPair([a, b])}
            />
          </div>
        </div>

        {dirty && isAdmin && (
          <div className="sticky bottom-4 z-20 mx-auto flex w-fit items-center gap-3 rounded-full border bg-popover/95 py-2 pr-2 pl-4 text-sm shadow-lg backdrop-blur">
            <span className="size-2 rounded-full bg-warning" />
            Unsaved changes
            <Button variant="ghost" size="sm" className="rounded-full" onClick={discard}>
              <LuUndo2 /> Discard
            </Button>
            <Button size="sm" className="rounded-full" onClick={() => setSaveOpen(true)} disabled={create.isPending}>
              <LuSave /> Save draft
            </Button>
          </div>
        )}

        <Dialog open={saveOpen} onOpenChange={setSaveOpen}>
          <DialogContent className="sm:max-w-md">
            <form onSubmit={save} className="grid gap-4">
              <DialogHeader>
                <DialogTitle>Save new version</DialogTitle>
                <DialogDescription>
                  Creates draft v{(versions[0]?.version ?? 0) + 1}. Nodes keep running the live version until you publish it.
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-2">
                <Label htmlFor="version-comment">What changed?</Label>
                <Textarea id="version-comment" name="comment" placeholder="e.g. raise trust2 weight, add 103.x ACL" autoFocus />
              </div>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setSaveOpen(false)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={create.isPending}>
                  {create.isPending ? 'Saving…' : 'Save draft'}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>

        <VersionDiffDialog profileId={profile.id} versions={versions} pair={diffPair} onClose={() => setDiffPair(null)} />

        <Discard
          open={blocker.state === 'blocked' || pendingLoad !== null}
          what={pendingLoad ? `Load v${pendingLoad.version}` : 'Leave page'}
          onCancel={() => (pendingLoad ? setPendingLoad(null) : blocker.reset?.())}
          onConfirm={() => (pendingLoad ? load(pendingLoad) : blocker.proceed?.())}
        />
      </ReadOnlyContext>
    </SpecErrorsContext>
  )
}

function Discard({ open, what, onCancel, onConfirm }: { open: boolean; what: string; onCancel: () => void; onConfirm: () => void }) {
  return (
    <AlertDialog open={open} onOpenChange={(o) => !o && onCancel()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Discard unsaved changes?</AlertDialogTitle>
          <AlertDialogDescription>Your edits to this profile have not been saved as a version and will be lost.</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Keep editing</AlertDialogCancel>
          <AlertDialogAction
            className={buttonVariants({ variant: 'destructive' })}
            onClick={(e) => {
              e.preventDefault() // closed via `open`, so onCancel doesn't fire too
              onConfirm()
            }}
          >
            {what}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
