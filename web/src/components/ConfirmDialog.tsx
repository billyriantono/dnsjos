import { useState, type ReactNode } from 'react'

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog'
import { Input } from '@/components/ui/input'

/**
 * Confirmation wrapper: `<ConfirmDialog title="Delete node?" onConfirm={…}><Button>Delete</Button></ConfirmDialog>`.
 * The dialog stays open (button disabled) while an async onConfirm is pending.
 * `confirmText` makes it a strong confirm: the user has to type that text first.
 */
export function ConfirmDialog({
  children,
  title,
  description,
  confirmLabel = 'Confirm',
  destructive,
  confirmText,
  onConfirm,
}: {
  children: ReactNode
  title: string
  description?: ReactNode
  confirmLabel?: string
  destructive?: boolean
  confirmText?: string
  onConfirm: () => unknown | Promise<unknown>
}) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [typed, setTyped] = useState('')
  const confirm = async (e: React.MouseEvent) => {
    e.preventDefault()
    setBusy(true)
    try {
      await onConfirm()
      setOpen(false)
    } finally {
      setBusy(false)
    }
  }
  return (
    <AlertDialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o)
        setTyped('')
      }}
    >
      <AlertDialogTrigger asChild>{children}</AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          {description && <AlertDialogDescription>{description}</AlertDialogDescription>}
        </AlertDialogHeader>
        {confirmText && (
          <label className="grid gap-1.5 text-sm">
            <span>
              Type <b className="font-mono">{confirmText}</b> to confirm
            </span>
            <Input value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} />
          </label>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            disabled={busy || (!!confirmText && typed !== confirmText)}
            onClick={confirm}
            variant={destructive ? 'destructive' : 'default'}
          >
            {confirmLabel}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
