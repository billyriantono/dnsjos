import { LuServer } from 'react-icons/lu'
import { Link } from 'react-router'

import { StatusBadge } from '@/components/StatusBadge'
import { Button } from '@/components/ui/button'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import type { Node, Profile } from '@/lib/api/types'

/** Nodes running a profile; nodes without one follow "default" (SPEC §10). */
// eslint-disable-next-line react-refresh/only-export-components
export const nodesUsing = (p: Profile, all: Node[] | undefined) =>
  all?.filter((n) => n.profile_id === p.id || (!n.profile_id && p.name === 'default'))

/** "N nodes" button that opens the list of nodes assigned to a profile. */
export function ProfileNodes({ profile, all }: { profile: Profile; all: Node[] | undefined }) {
  const nodes = nodesUsing(profile, all)
  const count = nodes?.length ?? profile.nodes
  if (count === 0) return <span className="text-sm text-muted-foreground">No nodes</span>
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className="h-7 gap-1.5 tabular" onClick={(e) => e.stopPropagation()}>
          <LuServer className="size-3.5" /> {count} node{count === 1 ? '' : 's'}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-72 p-1" onClick={(e) => e.stopPropagation()}>
        {!nodes ? (
          <p className="p-2 text-sm text-muted-foreground">Loading…</p>
        ) : (
          <ul className="max-h-72 overflow-y-auto">
            {nodes.map((n) => (
              <li key={n.id}>
                <Link to={`/nodes/${n.id}`} className="flex items-center justify-between gap-2 rounded-sm px-2 py-1.5 text-sm hover:bg-accent">
                  <span className="truncate">{n.name}</span>
                  <StatusBadge status={n.status} />
                </Link>
              </li>
            ))}
          </ul>
        )}
      </PopoverContent>
    </Popover>
  )
}
