import { useAuth } from '@/app/auth'
import { useUsers } from '@/lib/api/client'

/**
 * Email for a user id. The users list is admin-only, so viewers (and deleted users) see a short id.
 * ponytail: resolved client-side; if viewers need names, have the API return created_by_email.
 */
export function UserName({ id }: { id: string }) {
  const { isAdmin } = useAuth()
  const users = useUsers(isAdmin)
  const u = users.data?.items.find((x) => x.id === id)
  return <span title={id}>{u?.email ?? id.slice(0, 8)}</span>
}
