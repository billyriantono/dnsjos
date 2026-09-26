import { LuTrash2 } from 'react-icons/lu'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/ConfirmDialog'
import { DataTable, type Column } from '@/components/DataTable'
import { toastError } from '@/components/ops/toast'
import { TimeAgo } from '@/components/TimeAgo'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useDeleteEnrollmentToken, useEnrollmentTokens } from '@/lib/api/client'
import type { EnrollmentToken } from '@/lib/api/types'
import { pendingTokens } from '@/lib/enrollment'

/** Unused, unexpired enrollment tokens with a Revoke button. Admin-only; hidden when there are none. */
export function PendingEnrollments() {
  const tokens = useEnrollmentTokens()
  const remove = useDeleteEnrollmentToken()
  const pending = pendingTokens(tokens.data?.items ?? [])
  if (!pending.length) return null

  const columns: Column<EnrollmentToken>[] = [
    { key: 'name', header: 'Node name', cell: (t) => t.node_name || <span className="text-muted-foreground italic">hostname</span> },
    { key: 'created', header: 'Created', sortValue: (t) => t.created_at, cell: (t) => <TimeAgo date={t.created_at} /> },
    { key: 'expires', header: 'Expires', sortValue: (t) => t.expires_at, cell: (t) => <TimeAgo date={t.expires_at} /> },
    {
      key: 'actions',
      header: '',
      align: 'right',
      cell: (t) => (
        <ConfirmDialog
          title="Revoke enrollment token?"
          description="Its install command stops working immediately."
          confirmLabel="Revoke"
          destructive
          onConfirm={() => remove.mutateAsync(t.id).then(() => toast.success('Token revoked'), toastError)}
        >
          <Button variant="ghost" size="sm" className="text-destructive">
            <LuTrash2 /> Revoke
          </Button>
        </ConfirmDialog>
      ),
    },
  ]
  return (
    <Card className="mt-4">
      <CardHeader>
        <CardTitle>Pending enrollments</CardTitle>
        <CardDescription>Install commands that have not been used yet. Revoke any that were shared by mistake.</CardDescription>
      </CardHeader>
      <CardContent className="px-0">
        <DataTable columns={columns} rows={pending} rowKey={(t) => t.id} defaultSort={{ key: 'created', desc: true }} />
      </CardContent>
    </Card>
  )
}
