import { useState } from 'react'
import { LuChevronsUpDown } from 'react-icons/lu'

import { Checkbox } from '@/components/ui/checkbox'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { Button } from '@/components/ui/button'
import { profileLabel } from '@/pages/blocklist/profiles'
import type { BlocklistProfile } from '@/lib/api/types'

/**
 * Multi-select for a source's / RPZ master's config profile set. An empty selection means
 * the global scope (shared by every profile that has no build of its own), matching the
 * API: profile_ids [] is global, otherwise the source is built for exactly those profiles.
 */
export function ProfileMultiSelect({
  id,
  profiles,
  value,
  onChange,
  disabled,
}: {
  id?: string
  profiles: BlocklistProfile[] | undefined
  value: string[]
  onChange: (ids: string[]) => void
  disabled?: boolean
}) {
  const [open, setOpen] = useState(false)
  const names = value.map((pid) => profileLabel(profiles, pid))
  const label = value.length === 0 ? 'Global (shared by every profile)' : names.join(', ')

  const toggle = (pid: string, on: boolean) => {
    onChange(on ? [...value, pid] : value.filter((v) => v !== pid))
  }

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          id={id}
          type="button"
          variant="outline"
          role="combobox"
          aria-expanded={open}
          disabled={disabled}
          className="w-full justify-between font-normal"
        >
          <span className="truncate" title={label}>
            {label}
          </span>
          <LuChevronsUpDown className="ml-2 size-4 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-(--radix-popover-trigger-width) p-1">
        <label className="flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-sm hover:bg-accent">
          <Checkbox checked={value.length === 0} onCheckedChange={() => onChange([])} />
          Global (shared by every profile)
        </label>
        <div className="my-1 h-px bg-border" />
        {profiles?.length ? (
          profiles.map((p) => (
            <label
              key={p.id}
              className="flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-sm hover:bg-accent"
            >
              <Checkbox
                checked={value.includes(p.id)}
                onCheckedChange={(on) => toggle(p.id, on === true)}
              />
              <span className="truncate">{p.name}</span>
            </label>
          ))
        ) : (
          <div className="px-2 py-1.5 text-xs text-muted-foreground">No profiles</div>
        )}
      </PopoverContent>
    </Popover>
  )
}
