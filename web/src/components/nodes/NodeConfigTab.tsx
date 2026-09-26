import { useState } from 'react'
import { LuFileCode, LuSave } from 'react-icons/lu'
import { toast } from 'sonner'

import { useAuth } from '@/app/auth'
import { CopyButton } from '@/components/CopyButton'
import { EmptyState } from '@/components/EmptyState'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Textarea } from '@/components/ui/textarea'
import { useNodeRendered, useProfiles, useUpdateNode } from '@/lib/api/client'
import type { Node, NodePatch } from '@/lib/api/types'

const SPEC_FILE = 'effective-spec.json'
const FOLLOW = 'follow-default' // Radix Select can't hold '' (= follow `default`, SPEC §10)

// Belt and braces: the API already masks node secrets; re-mask anything that slipped through.
const mask = (s: string) =>
  s.replace(/((?:setKey\(|password\s*=\s*|apiKey\s*=\s*)["'])([^"']+)(["'])/g, (_, a: string, v: string, b: string) =>
    /^\*+$|^<.*>$/.test(v) ? a + v + b : `${a}********${b}`,
  )

const toText = (o: unknown) => (o == null || (typeof o === 'object' && !Object.keys(o).length) ? '' : JSON.stringify(o, null, 2))

export function NodeConfigTab({ node }: { node: Node }) {
  const { isAdmin } = useAuth()
  const profiles = useProfiles()
  const rendered = useNodeRendered(node.id)
  const update = useUpdateNode()
  const [profile, setProfile] = useState(node.profile_id ?? FOLLOW)
  const [text, setText] = useState(() => toText(node.overrides))
  const [apiError, setApiError] = useState('')

  let parseError = ''
  let parsed: unknown = null
  if (text.trim()) {
    try {
      parsed = JSON.parse(text)
      if (typeof parsed !== 'object' || Array.isArray(parsed) || parsed === null) parseError = 'Overrides must be a JSON object (RFC 7396 merge patch).'
    } catch (e) {
      parseError = (e as Error).message
    }
  }

  const save = (patch: NodePatch, what: string) =>
    update.mutate(
      { id: node.id, patch },
      {
        onSuccess: () => {
          setApiError('')
          toast.success(`${what} saved`, { description: 'The node applies it on its next config poll.' })
        },
        onError: (e) => {
          setApiError(e.message)
          toast.error(`${what} rejected`, { description: e.message })
        },
      },
    )

  const files: Record<string, string> | undefined = rendered.data ? { ...rendered.data.files, [SPEC_FILE]: JSON.stringify(rendered.data.spec, null, 2) } : undefined
  const names = files ? Object.keys(files).sort((a, b) => (a === 'dnsdist.conf' ? -1 : b === 'dnsdist.conf' ? 1 : a.localeCompare(b))) : []

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
        <Card className="gap-3 py-4">
          <CardHeader className="px-4">
            <CardTitle className="text-sm">Profile</CardTitle>
            <CardDescription className="text-xs">The node runs the newest published version of this profile.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 px-4">
            <Select value={profile} onValueChange={setProfile} disabled={!isAdmin}>
              <SelectTrigger className="w-full" aria-label="Profile">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={FOLLOW}>Follow default</SelectItem>
                {profiles.data?.items.map((p) => (
                  <SelectItem key={p.id} value={p.id}>
                    {p.name}
                    {p.published_version != null && <span className="text-muted-foreground"> · v{p.published_version}</span>}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {isAdmin && (
              <Button
                size="sm"
                disabled={profile === (node.profile_id ?? FOLLOW) || update.isPending}
                onClick={() => save({ profile_id: profile === FOLLOW ? '' : profile }, 'Profile')}
              >
                <LuSave /> Save profile
              </Button>
            )}
          </CardContent>
        </Card>

        <Card className="gap-3 py-4">
          <CardHeader className="px-4">
            <CardTitle className="text-sm">Per-node overrides</CardTitle>
            <CardDescription className="text-xs">
              JSON merge patch over the profile spec, e.g. <code className="font-mono">{'{"listen":{"do53":{"addresses":["10.0.0.53:53"]}}}'}</code>. Leave empty for none.
            </CardDescription>
            {isAdmin && (
              <CardAction>
                <Button size="sm" disabled={!!parseError || update.isPending || text === toText(node.overrides)} onClick={() => save({ overrides: parsed }, 'Overrides')}>
                  <LuSave /> Save overrides
                </Button>
              </CardAction>
            )}
          </CardHeader>
          <CardContent className="space-y-2 px-4">
            <Textarea
              value={text}
              onChange={(e) => {
                setText(e.target.value)
                setApiError('')
              }}
              readOnly={!isAdmin}
              spellCheck={false}
              rows={10}
              placeholder="{}"
              aria-invalid={!!(parseError || apiError)}
              className="font-mono text-xs"
            />
            {(parseError || apiError) && (
              <p className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 font-mono text-xs whitespace-pre-wrap text-destructive">
                {parseError || apiError}
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="gap-3 py-4">
        <CardHeader className="px-4">
          <CardTitle className="text-sm">Rendered configuration</CardTitle>
          <CardDescription className="text-xs">What the agent writes under /etc/dnsdist for the saved settings. Node secrets are masked.</CardDescription>
        </CardHeader>
        <CardContent className="px-4">
          {rendered.isPending ? (
            <Skeleton className="h-96" />
          ) : rendered.isError ? (
            <EmptyState icon={LuFileCode} title="Preview unavailable" description={rendered.error.message} />
          ) : (
            <Tabs defaultValue="dnsdist.conf">
              <TabsList className="h-auto flex-wrap">
                {names.map((n) => (
                  <TabsTrigger key={n} value={n} className="font-mono text-xs">
                    {n}
                  </TabsTrigger>
                ))}
              </TabsList>
              {names.map((n) => {
                const body = mask(files![n])
                return (
                  <TabsContent key={n} value={n} className="relative">
                    <CopyButton value={body} className="absolute top-2 right-2 z-10" />
                    <pre tabIndex={0} className="max-h-[32rem] overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-xs leading-relaxed">
                      <code>{body}</code>
                    </pre>
                  </TabsContent>
                )
              })}
            </Tabs>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
