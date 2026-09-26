import { useState } from 'react'
import { LuFileCode } from 'react-icons/lu'

import { CopyButton } from '@/components/CopyButton'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ApiError, usePreview } from '@/lib/api/client'
import { parseSpecErrors, type SpecErrors } from '@/lib/api/profiles'
import type { ConfigSpec } from '@/lib/api/types'

/** "Preview rendered config": renders the unsaved draft on the server (validated, not saved). */
export function PreviewDialog({
  profileId,
  spec,
  onErrors,
}: {
  profileId: string
  spec: ConfigSpec
  onErrors: (e: SpecErrors) => void
}) {
  const [open, setOpen] = useState(false)
  const preview = usePreview()
  const files = preview.data ? Object.keys(preview.data.files).sort((a, b) => (a === 'dnsdist.conf' ? -1 : b === 'dnsdist.conf' ? 1 : a.localeCompare(b))) : []

  const show = () => {
    setOpen(true)
    preview.mutate(
      { id: profileId, spec },
      {
        onSuccess: () => onErrors({}),
        onError: (e) => {
          if (e instanceof ApiError && e.status < 500) onErrors(parseSpecErrors(e.message))
        },
      },
    )
  }

  return (
    <>
      <Button variant="outline" onClick={show}>
        <LuFileCode /> Preview config
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="flex max-h-[90svh] flex-col sm:max-w-5xl">
          <DialogHeader>
            <DialogTitle>Rendered config</DialogTitle>
            <DialogDescription>
              Files the agent writes under /etc/dnsdist/ for this draft (unsaved changes included, node secrets masked,
              per-node overrides not applied).
            </DialogDescription>
          </DialogHeader>
          {preview.isPending ? (
            <div className="grid gap-2">
              <Skeleton className="h-9 w-80" />
              <Skeleton className="h-96 w-full" />
            </div>
          ) : preview.isError ? (
            <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm whitespace-pre-wrap text-destructive">
              {preview.error.message}
            </div>
          ) : (
            files.length > 0 && (
              <Tabs defaultValue={files[0]} className="min-h-0 flex-1">
                <TabsList className="max-w-full overflow-x-auto">
                  {files.map((f) => (
                    <TabsTrigger key={f} value={f} className="font-mono text-xs">
                      {f}
                    </TabsTrigger>
                  ))}
                </TabsList>
                {files.map((f) => (
                  <TabsContent key={f} value={f} className="relative min-h-0">
                    <CopyButton value={preview.data?.files[f] ?? ''} className="absolute top-2 right-4 z-10" />
                    <pre tabIndex={0} className="h-full max-h-[65svh] overflow-auto rounded-md border bg-muted/40 p-4 font-mono text-xs leading-relaxed">
                      {preview.data?.files[f]}
                    </pre>
                  </TabsContent>
                ))}
              </Tabs>
            )
          )}
        </DialogContent>
      </Dialog>
    </>
  )
}
