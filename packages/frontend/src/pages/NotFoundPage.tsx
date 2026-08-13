import { Link, useLocation } from 'react-router-dom'
import { Compass, ArrowLeft } from 'lucide-react'

/**
 * Catch-all for the authenticated shell. Without it React Router renders
 * nothing for an unknown path and the user sees an empty body under the
 * header/sidebar, which reads as a broken app rather than a bad link.
 */
export default function NotFoundPage() {
  const location = useLocation()

  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center text-center">
      <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-muted">
        <Compass className="text-muted-foreground" size={26} />
      </div>
      <h1 className="text-2xl font-bold">Page not found</h1>
      <p className="mt-2 max-w-md text-muted-foreground">
        There is nothing at{' '}
        <code className="rounded bg-muted px-1.5 py-0.5 text-sm">{location.pathname}</code>. The
        link may be out of date or the page may have moved.
      </p>
      <Link
        to="/"
        className="mt-6 inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
      >
        <ArrowLeft size={16} />
        Back to dashboard
      </Link>
    </div>
  )
}
