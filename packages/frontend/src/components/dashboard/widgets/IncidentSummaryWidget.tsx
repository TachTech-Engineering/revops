import { useListIncidentsQuery } from '../../../api/pantherApi'

const statusColors: Record<string, string> = {
  open: 'text-red-400',
  investigating: 'text-yellow-400',
  contained: 'text-blue-400',
  resolved: 'text-green-400',
  closed: 'text-muted-foreground',
}

export default function IncidentSummaryWidget() {
  const { data, isLoading } = useListIncidentsQuery({ page: 1, page_size: 100 })

  if (isLoading) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary"></div>
      </div>
    )
  }

  const incidents = data?.items || []
  const statusCounts = incidents.reduce((acc, inc) => {
    acc[inc.status] = (acc[inc.status] || 0) + 1
    return acc
  }, {} as Record<string, number>)

  const openCount = (statusCounts['open'] || 0) + (statusCounts['investigating'] || 0)

  return (
    <div className="h-full flex flex-col justify-center p-4">
      <div className="text-4xl font-bold text-foreground mb-1">{incidents.length}</div>
      <div className="text-sm text-muted-foreground mb-4">Total Incidents</div>

      <div className="grid grid-cols-2 gap-2 text-sm">
        <div>
          <span className={`font-semibold ${statusColors.open}`}>{statusCounts['open'] || 0}</span>
          <span className="text-muted-foreground ml-1">Open</span>
        </div>
        <div>
          <span className={`font-semibold ${statusColors.investigating}`}>{statusCounts['investigating'] || 0}</span>
          <span className="text-muted-foreground ml-1">Investigating</span>
        </div>
        <div>
          <span className={`font-semibold ${statusColors.contained}`}>{statusCounts['contained'] || 0}</span>
          <span className="text-muted-foreground ml-1">Contained</span>
        </div>
        <div>
          <span className={`font-semibold ${statusColors.resolved}`}>{statusCounts['resolved'] || 0}</span>
          <span className="text-muted-foreground ml-1">Resolved</span>
        </div>
      </div>

      {openCount > 0 && (
        <div className="mt-4 p-2 bg-red-500/20 rounded text-sm text-red-400">
          {openCount} incident{openCount > 1 ? 's' : ''} need attention
        </div>
      )}
    </div>
  )
}
