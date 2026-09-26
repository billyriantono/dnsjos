import { LuPower, LuRotateCw, LuTrash2 } from 'react-icons/lu'
import type { IconType } from 'react-icons'
import type { ReactNode } from 'react'
import { useNavigate } from 'react-router'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/ConfirmDialog'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { useDeleteNode, useNodeCommand } from '@/lib/api/client'
import type { CommandType, Node } from '@/lib/api/types'
import { cn } from '@/lib/utils'

function Action({ icon: Icon, title, description, children, danger }: { icon: IconType; title: string; description: string; children: ReactNode; danger?: boolean }) {
  return (
    <Card className={cn('py-4', danger && 'border-destructive/40')}>
      <CardContent className="flex flex-wrap items-center gap-4 px-4">
        <span className={cn('flex size-9 items-center justify-center rounded-md', danger ? 'bg-destructive/10 text-destructive' : 'bg-primary/10 text-primary')}>
          <Icon className="size-4" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="font-medium">{title}</p>
          <p className="text-sm text-muted-foreground">{description}</p>
        </div>
        {children}
      </CardContent>
    </Card>
  )
}

export function NodeActionsTab({ node }: { node: Node }) {
  const cmd = useNodeCommand()
  const del = useDeleteNode()
  const nav = useNavigate()

  const run = (type: CommandType, label: string) =>
    cmd.mutateAsync({ id: node.id, type }).then(
      () => toast.success(`${label} queued`, { description: 'The agent runs it on its next heartbeat.' }),
      (e: Error) => toast.error(e.message),
    )

  const remove = () =>
    del.mutateAsync(node.id).then(
      () => {
        toast.success(`Node ${node.name} deleted`)
        nav('/nodes')
      },
      (e: Error) => toast.error(e.message),
    )

  return (
    <div className="max-w-3xl space-y-3">
      <Action icon={LuPower} title="Restart dnsdist" description="Restarts the dnsdist service. Clients see a few seconds of failed queries.">
        <ConfirmDialog title="Restart dnsdist?" description={`dnsdist on ${node.name} stops answering briefly while it restarts.`} confirmLabel="Restart" onConfirm={() => run('restart_dnsdist', 'Restart')}>
          <Button variant="outline">Restart</Button>
        </ConfirmDialog>
      </Action>
      <Action icon={LuRotateCw} title="Reapply configuration" description="Re-renders and re-applies the current config, with validation and automatic rollback.">
        <ConfirmDialog title="Reapply configuration?" description="The agent re-renders the config and restarts dnsdist if it changed." confirmLabel="Reapply" onConfirm={() => run('reapply', 'Reapply')}>
          <Button variant="outline">Reapply</Button>
        </ConfirmDialog>
      </Action>
      <Action danger icon={LuTrash2} title="Delete node" description="Removes the node and revokes its token. dnsdist keeps running on the host with its last config.">
        <ConfirmDialog
          destructive
          title={`Delete ${node.name}?`}
          description="The agent loses access immediately. To add the host back you need a new enrollment token."
          confirmLabel="Delete node"
          onConfirm={remove}
        >
          <Button variant="destructive">Delete</Button>
        </ConfirmDialog>
      </Action>
    </div>
  )
}
