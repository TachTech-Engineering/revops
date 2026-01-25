import { useListCasesQuery } from '../../../api/pantherApi'

const statusColors: Record<string, string> = {
  open: 'text-red-600',
  in_progress: 'text-yellow-600',
  pending: 'text-purple-600',
  resolved: 'text-green-600',
  closed: 'text-gray-600',
}

export default function CaseSummaryWidget() {
  const { data, isLoading } = useListCasesQuery({ page: 1, page_size: 100 })

  if (isLoading) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  const cases = data?.items || []
  const statusCounts = cases.reduce((acc, c) => {
    acc[c.status] = (acc[c.status] || 0) + 1
    return acc
  }, {} as Record<string, number>)

  const activeCount = (statusCounts['open'] || 0) + (statusCounts['in_progress'] || 0)

  return (
    <div className="h-full flex flex-col justify-center p-4">
      <div className="text-4xl font-bold text-gray-900 mb-1">{cases.length}</div>
      <div className="text-sm text-gray-500 mb-4">Total Cases</div>

      <div className="grid grid-cols-2 gap-2 text-sm">
        <div>
          <span className={`font-semibold ${statusColors.open}`}>{statusCounts['open'] || 0}</span>
          <span className="text-gray-500 ml-1">Open</span>
        </div>
        <div>
          <span className={`font-semibold ${statusColors.in_progress}`}>{statusCounts['in_progress'] || 0}</span>
          <span className="text-gray-500 ml-1">In Progress</span>
        </div>
        <div>
          <span className={`font-semibold ${statusColors.pending}`}>{statusCounts['pending'] || 0}</span>
          <span className="text-gray-500 ml-1">Pending</span>
        </div>
        <div>
          <span className={`font-semibold ${statusColors.resolved}`}>{statusCounts['resolved'] || 0}</span>
          <span className="text-gray-500 ml-1">Resolved</span>
        </div>
      </div>

      {activeCount > 0 && (
        <div className="mt-4 p-2 bg-yellow-50 rounded text-sm text-yellow-700">
          {activeCount} active case{activeCount > 1 ? 's' : ''}
        </div>
      )}
    </div>
  )
}
