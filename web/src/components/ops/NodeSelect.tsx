import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { useNodes } from '@/lib/api/client'

const ALL = '__all__'

/** Node filter; value '' means all nodes. */
export function NodeSelect({ value, onChange, className }: { value: string; onChange: (id: string) => void; className?: string }) {
  const { data } = useNodes()
  return (
    <Select value={value || ALL} onValueChange={(v) => onChange(v === ALL ? '' : v)}>
      <SelectTrigger className={className ?? 'w-48'} aria-label="Node">
        <SelectValue placeholder="All nodes" />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={ALL}>All nodes</SelectItem>
        {data?.items.map((n) => (
          <SelectItem key={n.id} value={n.id}>
            {n.name}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}
