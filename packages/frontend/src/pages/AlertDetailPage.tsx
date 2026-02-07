import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import {
  useGetAlertQuery,
  useGetAlertEventsQuery,
  useUpdateAlertMutation,
  useAddAlertCommentMutation
} from '../api/pantherApi'
import { getSeverityColor, getStatusColor, formatDate } from '../lib/utils'
import type { AlertStatus } from '../types'
import TriageSuggestionBadge from '../components/triage/TriageSuggestionBadge'

export default function AlertDetailPage() {
  const { alertId } = useParams<{ alertId: string }>()
  const [commentBody, setCommentBody] = useState('')

  // Skip query if alertId is not available
  const { data: alert, isLoading, isFetching, error } = useGetAlertQuery(alertId ?? '', { skip: !alertId })
  const { data: eventsData } = useGetAlertEventsQuery(
    { alertId: alertId ?? '', pageSize: 20 },
    { skip: !alertId }
  )

  // Debug logging
  console.log('AlertDetailPage render:', { alertId, isLoading, isFetching, error, hasAlert: !!alert })
  const [updateAlert] = useUpdateAlertMutation()
  const [addComment, { isLoading: isAddingComment }] = useAddAlertCommentMutation()

  const handleStatusChange = async (newStatus: AlertStatus) => {
    if (!alertId) return
    try {
      await updateAlert({ id: alertId, status: newStatus }).unwrap()
    } catch (err) {
      console.error('Failed to update alert:', err)
    }
  }

  const handleAddComment = async () => {
    if (!alertId || !commentBody.trim()) return
    try {
      await addComment({ alertId, body: commentBody }).unwrap()
      setCommentBody('')
    } catch (err) {
      console.error('Failed to add comment:', err)
    }
  }

  if (!alertId) {
    return <div className="p-6 text-center text-red-500">No alert ID provided</div>
  }

  if (isLoading || isFetching) {
    return <div className="p-6 text-center">Loading alert...</div>
  }

  if (error) {
    let errorMessage = 'Unknown error'
    if (typeof error === 'object' && error !== null) {
      if ('status' in error) {
        errorMessage = `Error ${(error as { status: number }).status}: ${JSON.stringify((error as { data?: unknown }).data)}`
      } else if ('message' in error) {
        errorMessage = (error as { message: string }).message
      }
    }
    return (
      <div className="p-6 text-center">
        <p className="text-red-500 mb-2">Error loading alert</p>
        <p className="text-sm text-muted-foreground">{errorMessage}</p>
        <Link to="/alerts" className="text-primary hover:underline mt-4 inline-block">
          Back to Alerts
        </Link>
      </div>
    )
  }

  if (!alert) {
    return (
      <div className="p-6 text-center">
        <p className="text-muted-foreground">Alert not found</p>
        <Link to="/alerts" className="text-primary hover:underline mt-4 inline-block">
          Back to Alerts
        </Link>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Link to="/alerts" className="p-2 hover:bg-accent rounded-md">
          <ArrowLeft size={20} />
        </Link>
        <div className="flex-1">
          <h1 className="text-2xl font-bold">{alert.title}</h1>
          <p className="text-muted-foreground">{alert.detectionId}</p>
        </div>
        <div className="flex items-center gap-2">
          <span className={`px-3 py-1 rounded-full text-sm font-medium ${getSeverityColor(alert.severity)}`}>
            {alert.severity}
          </span>
          <select
            value={alert.status}
            onChange={(e) => handleStatusChange(e.target.value as AlertStatus)}
            className={`rounded-full px-3 py-1 text-sm font-medium border-0 ${getStatusColor(alert.status)}`}
          >
            <option value="OPEN">Open</option>
            <option value="TRIAGED">Triaged</option>
            <option value="CLOSED">Closed</option>
            <option value="RESOLVED">Resolved</option>
          </select>
        </div>
      </div>

      {/* AI Triage Suggestion */}
      <TriageSuggestionBadge alertId={alertId} />

      {/* Alert Details */}
      <div className="grid gap-6 md:grid-cols-2">
        <div className="rounded-lg border bg-background p-6 space-y-4">
          <h2 className="font-semibold">Details</h2>
          <dl className="space-y-2 text-sm">
            {alert.detectionName && (
              <div className="flex justify-between">
                <dt className="text-muted-foreground">Detection</dt>
                <dd className="font-medium">{alert.detectionName}</dd>
              </div>
            )}
            {alert.sourceType && (
              <div className="flex justify-between">
                <dt className="text-muted-foreground">Source</dt>
                <dd className="font-medium">{alert.sourceType}</dd>
              </div>
            )}
            {alert.eventCount !== undefined && (
              <div className="flex justify-between">
                <dt className="text-muted-foreground">Event Count</dt>
                <dd className="font-medium">{alert.eventCount}</dd>
              </div>
            )}
            {alert.logTypes && alert.logTypes.length > 0 && (
              <div className="flex justify-between">
                <dt className="text-muted-foreground">Log Types</dt>
                <dd className="font-medium">{alert.logTypes.join(', ')}</dd>
              </div>
            )}
            <div className="flex justify-between">
              <dt className="text-muted-foreground">Created</dt>
              <dd className="font-medium">{formatDate(alert.createdAt)}</dd>
            </div>
            {alert.updatedAt && (
              <div className="flex justify-between">
                <dt className="text-muted-foreground">Updated</dt>
                <dd className="font-medium">{formatDate(alert.updatedAt)}</dd>
              </div>
            )}
            {alert.firstEventAt && (
              <div className="flex justify-between">
                <dt className="text-muted-foreground">First Event</dt>
                <dd className="font-medium">{formatDate(alert.firstEventAt)}</dd>
              </div>
            )}
            {alert.lastEventAt && (
              <div className="flex justify-between">
                <dt className="text-muted-foreground">Last Event</dt>
                <dd className="font-medium">{formatDate(alert.lastEventAt)}</dd>
              </div>
            )}
            {alert.assigneeName && (
              <div className="flex justify-between">
                <dt className="text-muted-foreground">Assignee</dt>
                <dd className="font-medium">{alert.assigneeName}</dd>
              </div>
            )}
          </dl>
          {alert.description && (
            <div className="pt-4 border-t">
              <h3 className="text-sm font-medium mb-2">Description</h3>
              <p className="text-sm text-muted-foreground">{alert.description}</p>
            </div>
          )}
          {alert.tags && alert.tags.length > 0 && (
            <div className="pt-4 border-t">
              <h3 className="text-sm font-medium mb-2">Tags</h3>
              <div className="flex flex-wrap gap-2">
                {alert.tags.map((tag) => (
                  <span key={tag} className="px-2 py-1 bg-muted rounded text-xs">
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}
          {alert.mitreTactics && alert.mitreTactics.length > 0 && (
            <div className="pt-4 border-t">
              <h3 className="text-sm font-medium mb-2">MITRE Tactics</h3>
              <div className="flex flex-wrap gap-2">
                {alert.mitreTactics.map((tactic) => (
                  <span key={tactic} className="px-2 py-1 bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded text-xs">
                    {tactic}
                  </span>
                ))}
              </div>
            </div>
          )}
          {alert.mitreTechniques && alert.mitreTechniques.length > 0 && (
            <div className="pt-4 border-t">
              <h3 className="text-sm font-medium mb-2">MITRE Techniques</h3>
              <div className="flex flex-wrap gap-2">
                {alert.mitreTechniques.map((technique) => (
                  <span key={technique} className="px-2 py-1 bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-200 rounded text-xs">
                    {technique}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Add Comment */}
        <div className="rounded-lg border bg-background p-6 space-y-4">
          <h2 className="font-semibold">Add Comment</h2>
          <textarea
            value={commentBody}
            onChange={(e) => setCommentBody(e.target.value)}
            placeholder="Write a comment..."
            className="w-full h-24 rounded-md border bg-background px-3 py-2 text-sm resize-none"
          />
          <button
            onClick={handleAddComment}
            disabled={isAddingComment || !commentBody.trim()}
            className="px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium disabled:opacity-50"
          >
            {isAddingComment ? 'Adding...' : 'Add Comment'}
          </button>
        </div>
      </div>

      {/* Events */}
      {eventsData?.results && eventsData.results.length > 0 && (
        <div className="rounded-lg border bg-background">
          <div className="border-b px-6 py-4">
            <h2 className="font-semibold">Events ({eventsData.results.length})</h2>
          </div>
          <div className="divide-y max-h-96 overflow-auto">
            {eventsData.results.map((event) => (
              <div key={event.eventId} className="px-6 py-4">
                <div className="flex justify-between items-start mb-2">
                  <span className="text-sm font-medium">{event.logType}</span>
                  <span className="text-sm text-muted-foreground">
                    {formatDate(event.eventTime)}
                  </span>
                </div>
                <pre className="text-xs bg-muted p-2 rounded overflow-x-auto">
                  {JSON.stringify(event.data, null, 2)}
                </pre>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Raw Data */}
      {alert.rawData && (
        <div className="rounded-lg border bg-background">
          <div className="border-b px-6 py-4">
            <h2 className="font-semibold">Raw Alert Data</h2>
          </div>
          <div className="p-6">
            <pre className="text-xs bg-muted p-4 rounded overflow-x-auto max-h-96">
              {JSON.stringify(alert.rawData, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  )
}
