import { RequireAdmin } from '@/app/auth'
import { PageHeader } from '@/components/PageHeader'
import { AddNodeDialog } from '@/components/nodes/AddNodeDialog'
import { NodesTable } from '@/components/nodes/NodesTable'
import { PendingEnrollments } from '@/components/nodes/PendingEnrollments'
import { useNodes } from '@/lib/api/client'

export default function NodesPage() {
  const nodes = useNodes()
  return (
    <>
      <PageHeader
        title="Nodes"
        description="dnsdist resolvers managed by this panel."
        actions={
          <RequireAdmin>
            <AddNodeDialog />
          </RequireAdmin>
        }
      />
      <NodesTable rows={nodes.data?.items} loading={nodes.isPending} error={nodes.error} />
      <RequireAdmin>
        <PendingEnrollments />
      </RequireAdmin>
    </>
  )
}
