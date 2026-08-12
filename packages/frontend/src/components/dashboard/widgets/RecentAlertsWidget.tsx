import { Link } from 'react-router-dom'
import { useListAlertsQuery } from '../../../api/pantherApi'

interface RecentAlertsWidgetProps {
  config?: { limit?: number }
}

const severityColors: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-800',
  HIGH: 'bg-orange-100 text-orange-800',
  MEDIUM: 'bg-yellow-100 text-yellow-800',
  LOW: 'bg-blue-100 text-blue-800',
  INFO: 'bg-gray-100 text-gray-800',
}

export default function RecentAlertsWidget({ config }: RecentAlertsWidgetProps) {
  const { data, isLoading } = useListAlertsQuery({
    pageSize: config?.limit || 5,
  })

  if (isLoading) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  if (!data?.results?.length) {
    return <div className="text-gray-500 text-center p-4">No recent alerts</div>
  }

  return (
    <div className="h-full overflow-auto">
      <table className="w-full text-sm">
        <thead className="bg-gray-50 sticky top-0">
          <tr>
            <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Alert</th>
            <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
            <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200">
          {data.results.map((alert) => (
            <tr key={alert.id} className="hover:bg-gray-50">
              <td className="px-3 py-2">
                <Link
                  to={`/alerts/${alert.id}`}
                  className="text-blue-600 hover:text-blue-800 line-clamp-1"
                >
                  {alert.title}
                </Link>
              </td>
              <td className="px-3 py-2">
                <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${severityColors[alert.severity] || 'bg-gray-100'}`}>
                  {alert.severity}
                </span>
              </td>
              <td className="px-3 py-2 text-gray-500 whitespace-nowrap">
                {new Date(alert.createdAt).toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
