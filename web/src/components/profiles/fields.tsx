import { useId, useState, type ClipboardEvent, type KeyboardEvent, type ReactNode } from 'react'
import { LuPlus, LuTrash2, LuX } from 'react-icons/lu'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { cn } from '@/lib/utils'
import { useFieldErrors, useListErrors, useReadOnly } from './context'

function Hint({ errors, help }: { errors: string[]; help?: ReactNode }) {
  if (errors.length) return <p className="text-xs text-destructive">{errors.join(' · ')}</p>
  return help ? <p className="text-xs text-muted-foreground">{help}</p> : null
}

/** Card for one config area; `enabled` adds a header switch and dims the body when off. */
export function Section({
  title,
  description,
  enabled,
  onEnabledChange,
  children,
  className,
}: {
  title: string
  description?: ReactNode
  enabled?: boolean
  onEnabledChange?: (v: boolean) => void
  children: ReactNode
  className?: string
}) {
  const ro = useReadOnly()
  return (
    <Card className={cn('gap-4', className)}>
      <CardHeader>
        <CardTitle className="text-base" role="heading" aria-level={2}>
          {title}
        </CardTitle>
        {description && <CardDescription>{description}</CardDescription>}
        {onEnabledChange && (
          <CardAction className="flex items-center gap-2 text-sm text-muted-foreground">
            {enabled ? 'Enabled' : 'Disabled'}
            <Switch checked={enabled} onCheckedChange={onEnabledChange} disabled={ro} aria-label={`${title} enabled`} />
          </CardAction>
        )}
      </CardHeader>
      <CardContent className={cn('grid gap-4 transition-opacity', enabled === false && 'opacity-60')}>
        {children}
      </CardContent>
    </Card>
  )
}

export function TextField({
  label,
  help,
  path,
  value,
  onChange,
  placeholder,
  mono = true,
  className,
}: {
  label: string
  help?: ReactNode
  path: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
  mono?: boolean
  className?: string
}) {
  const errors = useFieldErrors(path)
  return (
    <div className={cn('grid content-start gap-1.5', className)}>
      <Label htmlFor={path}>{label}</Label>
      <Input
        id={path}
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        aria-invalid={errors.length > 0 || undefined}
        readOnly={useReadOnly()}
        className={cn(mono && 'font-mono text-sm')}
      />
      <Hint errors={errors} help={help} />
    </div>
  )
}

export function NumField({
  label,
  help,
  path,
  value,
  onChange,
  min,
  max,
  unit,
  className,
}: {
  label: string
  help?: ReactNode
  path: string
  value: number
  onChange: (v: number) => void
  min?: number
  max?: number
  unit?: string
  className?: string
}) {
  const errors = useFieldErrors(path)
  return (
    <div className={cn('grid content-start gap-1.5', className)}>
      <Label htmlFor={path}>{label}</Label>
      <div className="relative">
        <Input
          id={path}
          type="number"
          inputMode="numeric"
          value={Number.isFinite(value) ? value : ''}
          min={min}
          max={max}
          onChange={(e) => onChange(e.target.value === '' ? 0 : Math.trunc(Number(e.target.value)))}
          aria-invalid={errors.length > 0 || undefined}
          readOnly={useReadOnly()}
          className={cn('tabular', unit && 'pr-14')}
        />
        {unit && (
          <span className="pointer-events-none absolute inset-y-0 right-3 flex items-center text-xs text-muted-foreground">
            {unit}
          </span>
        )}
      </div>
      <Hint errors={errors} help={help} />
    </div>
  )
}

export function SwitchField({
  label,
  help,
  checked,
  onChange,
}: {
  label: string
  help?: ReactNode
  checked: boolean
  onChange: (v: boolean) => void
}) {
  const id = useId()
  return (
    <div className="flex items-start justify-between gap-4 rounded-md border p-3">
      <div className="grid gap-1">
        <Label htmlFor={id}>{label}</Label>
        {help && <p className="text-xs text-muted-foreground">{help}</p>}
      </div>
      <Switch id={id} checked={checked} onCheckedChange={onChange} disabled={useReadOnly()} />
    </div>
  )
}

/**
 * Editable list of strings (CIDRs, ip:port, domains). Paste or type many values separated by
 * spaces, commas or newlines; valid ones are added (deduplicated), invalid ones stay in the input.
 */
export function ListEditor({
  label,
  help,
  path,
  value,
  onChange,
  validate,
  placeholder,
  what = 'value',
  className,
}: {
  label: string
  help?: ReactNode
  path: string
  value: string[]
  onChange: (v: string[]) => void
  validate: (s: string) => boolean
  placeholder?: string
  what?: string
  className?: string
}) {
  const ro = useReadOnly()
  const listErrors = useListErrors(path)
  const [input, setInput] = useState('')
  const [rejected, setRejected] = useState<string[]>([])

  const add = (text: string) => {
    const parts = text.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean)
    if (!parts.length) return
    const good = parts.filter(validate)
    const bad = parts.filter((p) => !validate(p))
    const next = [...value]
    for (const g of good) if (!next.includes(g)) next.push(g)
    if (next.length !== value.length) onChange(next)
    setRejected(bad)
    setInput(bad.join(' '))
  }
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      add(input)
    } else if (e.key === 'Backspace' && input === '' && value.length) onChange(value.slice(0, -1))
  }
  const onPaste = (e: ClipboardEvent<HTMLInputElement>) => {
    const text = e.clipboardData.getData('text')
    if (/[\s,;]/.test(text.trim())) {
      e.preventDefault()
      add(input + ' ' + text)
    }
  }
  const invalidCount = value.filter((v) => !validate(v)).length
  const own = listErrors.get(-1) ?? []

  return (
    <div className={cn('grid content-start gap-1.5', className)}>
      <div className="flex items-center justify-between gap-2">
        <Label htmlFor={path}>{label}</Label>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          {invalidCount > 0 && <span className="text-destructive">{invalidCount} invalid</span>}
          <span className="tabular">{value.length}</span>
          {!ro && value.length > 0 && (
            <Button type="button" variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={() => onChange([])}>
              <LuTrash2 /> Clear
            </Button>
          )}
        </div>
      </div>
      <div
        className={cn(
          'flex max-h-64 flex-wrap gap-1.5 overflow-y-auto rounded-md border bg-muted/20 p-2',
          listErrors.size > 0 && 'border-destructive',
        )}
      >
        {value.length === 0 && <span className="px-1 text-xs text-muted-foreground">Empty</span>}
        {value.map((v, i) => {
          const itemErrs = listErrors.get(i)
          const bad = !validate(v) || !!itemErrs
          return (
            <Badge
              key={v + i}
              variant="outline"
              title={itemErrs?.join(' · ')}
              className={cn('gap-1 font-mono font-normal', bad && 'border-destructive bg-destructive/10 text-destructive')}
            >
              {v}
              {!ro && (
                <button
                  type="button"
                  aria-label={`Remove ${v}`}
                  className="-mr-1 rounded-full p-0.5 opacity-60 hover:bg-foreground/10 hover:opacity-100"
                  onClick={() => onChange(value.filter((_, j) => j !== i))}
                >
                  <LuX className="size-3" />
                </button>
              )}
            </Badge>
          )
        })}
      </div>
      {!ro && (
        <div className="flex gap-2">
          <Input
            id={path}
            value={input}
            placeholder={placeholder ?? `Add ${what} — paste many at once`}
            onChange={(e) => {
              setInput(e.target.value)
              setRejected([])
            }}
            onKeyDown={onKey}
            onPaste={onPaste}
            aria-invalid={rejected.length > 0 || undefined}
            className="font-mono text-sm"
          />
          <Button type="button" variant="outline" onClick={() => add(input)} disabled={!input.trim()}>
            <LuPlus /> Add
          </Button>
        </div>
      )}
      <Hint
        errors={[
          ...own,
          ...(rejected.length ? [`Not a valid ${what}: ${rejected.join(', ')}`] : []),
          ...[...listErrors].filter(([i]) => i >= 0).map(([i, m]) => `#${i + 1} ${value[i] ?? ''}: ${m.join(', ')}`),
        ]}
        help={help}
      />
    </div>
  )
}
