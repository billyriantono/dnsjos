import { LuCompass } from 'react-icons/lu'
import { Link } from 'react-router'

import { EmptyState } from '@/components/EmptyState'
import { Button } from '@/components/ui/button'

export default function NotFound() {
  return (
    <EmptyState
      icon={LuCompass}
      title="Page not found"
      description="The page you are looking for does not exist or was moved."
      action={
        <Button asChild variant="outline">
          <Link to="/">Back to overview</Link>
        </Button>
      }
      className="py-24"
    />
  )
}
