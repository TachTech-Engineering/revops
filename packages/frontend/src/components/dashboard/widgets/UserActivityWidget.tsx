import { Link } from 'react-router-dom'
import {
  Users,
  RefreshCw,
  ChevronRight,
  Search,
  FileEdit,
  Eye,
  Shield,
  LogIn,
  Settings,
} from 'lucide-react'
import { cn } from '../../../lib/utils'

interface UserActivityWidgetProps {
  config?: {
    limit?: number
  }
}

// Mock data - in production this would come from an API
const useUserActivity = (limit: number = 10) => {
  return {
    data: {
      activities: [
        {
          id: '1',
          user_email: 'alice@company.com',
          user_name: 'Alice Chen',
          action: 'viewed_alert',
          resource: 'Alert #12345',
          timestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
        },
        {
          id: '2',
          user_email: 'bob@company.com',
          user_name: 'Bob Smith',
          action: 'updated_rule',
          resource: 'AWS.CloudTrail.UnauthorizedAPI',
          timestamp: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
        },
        {
          id: '3',
          user_email: 'carol@company.com',
          user_name: 'Carol Davis',
          action: 'ran_query',
          resource: 'IOC Search: 192.168.1.100',
          timestamp: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
        },
        {
          id: '4',
          user_email: 'dave@company.com',
          user_name: 'Dave Wilson',
          action: 'closed_incident',
          resource: 'Incident #INC-2024-001',
          timestamp: new Date(Date.now() - 45 * 60 * 1000).toISOString(),
        },
        {
          id: '5',
          user_email: 'eve@company.com',
          user_name: 'Eve Johnson',
          action: 'login',
          resource: 'Web Console',
          timestamp: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
        },
        {
          id: '6',
          user_email: 'alice@company.com',
          user_name: 'Alice Chen',
          action: 'updated_settings',
          resource: 'Notification Preferences',
          timestamp: new Date(Date.now() - 90 * 60 * 1000).toISOString(),
        },
      ].slice(0, limit),
      online_users: 12,
      total_actions_today: 458,
    },
    isLoading: false,
  }
}

const actionConfig: Record<string, { icon: typeof Search; color: string; label: string }> = {
  viewed_alert: { icon: Eye, color: 'text-blue-400', label: 'Viewed' },
  updated_rule: { icon: FileEdit, color: 'text-yellow-400', label: 'Updated' },
  ran_query: { icon: Search, color: 'text-purple-400', label: 'Queried' },
  closed_incident: { icon: Shield, color: 'text-green-400', label: 'Closed' },
  login: { icon: LogIn, color: 'text-cyan-400', label: 'Logged in' },
  updated_settings: { icon: Settings, color: 'text-gray-400', label: 'Settings' },
}

function timeAgo(timestamp: string): string {
  const seconds = Math.floor((Date.now() - new Date(timestamp).getTime()) / 1000)
  if (seconds < 60) return 'just now'
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

export default function UserActivityWidget({ config }: UserActivityWidgetProps) {
  const { data, isLoading } = useUserActivity(config?.limit || 6)

  if (isLoading) {
    return (
      <div className="h-full flex items-center justify-center">
        <RefreshCw className="animate-spin text-muted-foreground" size={24} />
      </div>
    )
  }

  if (!data) return null

  return (
    <div className="h-full flex flex-col p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-medium flex items-center gap-2">
          <Users size={16} className="text-primary" />
          User Activity
        </h3>
        <Link
          to="/audit"
          className="text-xs text-primary hover:underline flex items-center gap-1"
        >
          Audit Log <ChevronRight size={12} />
        </Link>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-2 mb-4">
        <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-2 text-center">
          <p className="text-lg font-bold text-green-400">{data.online_users}</p>
          <p className="text-xs text-muted-foreground">Online Now</p>
        </div>
        <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-2 text-center">
          <p className="text-lg font-bold text-blue-400">{data.total_actions_today}</p>
          <p className="text-xs text-muted-foreground">Actions Today</p>
        </div>
      </div>

      {/* Activity Feed */}
      <div className="flex-1 space-y-2 overflow-y-auto">
        {data.activities.map((activity) => {
          const actionInfo = actionConfig[activity.action] || actionConfig.viewed_alert
          const ActionIcon = actionInfo.icon
          return (
            <div
              key={activity.id}
              className="flex items-start gap-3 p-2 bg-muted/30 rounded-lg"
            >
              <div
                className={cn(
                  'w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0',
                  'bg-muted'
                )}
              >
                <ActionIcon size={14} className={actionInfo.color} />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">{activity.user_name}</p>
                <p className="text-xs text-muted-foreground truncate">
                  {actionInfo.label}: {activity.resource}
                </p>
              </div>
              <span className="text-xs text-muted-foreground flex-shrink-0">
                {timeAgo(activity.timestamp)}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
