import { toast } from 'sonner'

/** Mutation onError handler: toasts the API error message. */
export const toastError = (e: unknown) => toast.error(e instanceof Error ? e.message : 'Request failed')
