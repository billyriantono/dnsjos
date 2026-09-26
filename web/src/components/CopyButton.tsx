import { useState } from 'react'
import { LuCheck, LuCopy } from 'react-icons/lu'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'

export function CopyButton({ value, label, className }: { value: string; label?: string; className?: string }) {
  const [done, setDone] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setDone(true)
      setTimeout(() => setDone(false), 1500)
    } catch {
      toast.error('Copy failed — select the text and copy manually')
    }
  }
  return (
    <Button type="button" variant="outline" size={label ? 'sm' : 'icon'} className={className} onClick={copy} aria-label="Copy">
      {done ? <LuCheck className="text-success" /> : <LuCopy />}
      {label}
    </Button>
  )
}
