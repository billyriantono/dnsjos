import { useMemo, useState, type ReactNode } from 'react'
import { LuArrowDown, LuArrowUp, LuArrowUpDown, LuCircleAlert } from 'react-icons/lu'

import { EmptyState } from '@/components/EmptyState'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { cn } from '@/lib/utils'

type SortValue = string | number | boolean | null | undefined

export interface Column<T> {
  key: string
  header: ReactNode
  cell: (row: T) => ReactNode
  /** Enables sorting on this column. */
  sortValue?: (row: T) => SortValue
  align?: 'left' | 'right'
  className?: string
}

export interface DataTableProps<T> {
  columns: Column<T>[]
  rows: T[] | undefined
  rowKey: (row: T) => string | number
  loading?: boolean
  defaultSort?: { key: string; desc?: boolean }
  onRowClick?: (row: T) => void
  empty?: ReactNode
  /** Shown instead of `empty` when loading the rows failed. */
  error?: Error | null
  skeletonRows?: number
  className?: string
}

function compare(a: SortValue, b: SortValue) {
  // Nullish always sorts last regardless of direction handled by caller.
  if (a == null) return b == null ? 0 : 1
  if (b == null) return -1
  if (typeof a === 'string' && typeof b === 'string') return a.localeCompare(b, undefined, { numeric: true })
  return Number(a) - Number(b)
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  loading,
  defaultSort,
  onRowClick,
  empty,
  error,
  skeletonRows = 5,
  className,
}: DataTableProps<T>) {
  const [sort, setSort] = useState(defaultSort)

  const sorted = useMemo(() => {
    const col = sort && columns.find((c) => c.key === sort.key)
    if (!rows || !sort || !col?.sortValue) return rows ?? []
    const get = col.sortValue
    const dir = sort.desc ? -1 : 1
    return [...rows].sort((a, b) => {
      const va = get(a)
      const vb = get(b)
      if (va == null || vb == null) return compare(va, vb)
      return compare(va, vb) * dir
    })
  }, [rows, columns, sort])

  const toggle = (key: string) =>
    setSort((s) => (s?.key !== key ? { key, desc: false } : s.desc ? undefined : { key, desc: true }))

  return (
    <div className={cn('overflow-hidden rounded-lg border bg-card', className)}>
      <Table>
        <TableHeader className="bg-muted/40">
          <TableRow className="hover:bg-transparent">
            {columns.map((c) => {
              const active = sort?.key === c.key
              const Icon = !active ? LuArrowUpDown : sort.desc ? LuArrowDown : LuArrowUp
              return (
                <TableHead
                  key={c.key}
                  aria-sort={active ? (sort.desc ? 'descending' : 'ascending') : undefined}
                  className={cn('h-9 text-xs', c.align === 'right' && 'text-right', c.className)}
                >
                  {c.sortValue ? (
                    <button
                      type="button"
                      onClick={() => toggle(c.key)}
                      className={cn(
                        'inline-flex items-center gap-1 hover:text-foreground',
                        c.align === 'right' && 'flex-row-reverse',
                        active && 'text-foreground',
                      )}
                    >
                      {c.header}
                      <Icon className={cn('size-3', !active && 'opacity-40')} />
                    </button>
                  ) : (
                    c.header || <span className="sr-only">{c.key}</span>
                  )}
                </TableHead>
              )
            })}
          </TableRow>
        </TableHeader>
        <TableBody>
          {loading && !rows
            ? Array.from({ length: skeletonRows }, (_, i) => (
                <TableRow key={i} className="hover:bg-transparent">
                  {columns.map((c) => (
                    <TableCell key={c.key}>
                      <Skeleton className="h-4 w-full max-w-32" />
                    </TableCell>
                  ))}
                </TableRow>
              ))
            : sorted.map((row) => (
                <TableRow
                  key={rowKey(row)}
                  onClick={onRowClick && (() => onRowClick(row))}
                  className={cn(onRowClick && 'cursor-pointer')}
                >
                  {columns.map((c) => (
                    <TableCell key={c.key} className={cn('tabular', c.align === 'right' && 'text-right', c.className)}>
                      {c.cell(row)}
                    </TableCell>
                  ))}
                </TableRow>
              ))}
          {!loading && sorted.length === 0 && (
            <TableRow className="hover:bg-transparent">
              <TableCell colSpan={columns.length} className="p-0">
                {error ? (
                  <EmptyState icon={LuCircleAlert} title="Could not load data" description={error.message} />
                ) : (
                  (empty ?? <EmptyState title="Nothing here yet" />)
                )}
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </div>
  )
}
