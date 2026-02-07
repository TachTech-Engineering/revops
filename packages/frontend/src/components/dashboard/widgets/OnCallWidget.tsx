import { Link } from 'react-router-dom'
import {
  Calendar,
  RefreshCw,
  UserCheck,
  Users,
  ChevronRight,
  Clock,
  AlertTriangle,
} from 'lucide-react'
import { useGetCurrentOnCallQuery } from '../../../api/pantherApi'
import { cn } from '../../../lib/utils'

interface OnCallWidgetProps {
  config?: {
    showBackup?: boolean
  }
}

export default function OnCallWidget({ config }: OnCallWidgetProps) {
  const { data: currentOnCall, isLoading } = useGetCurrentOnCallQuery()

  if (isLoading) {
    return (
      <div className="h-full flex items-center justify-center">
        <RefreshCw className="animate-spin text-muted-foreground" size={24} />
      </div>
    )
  }

  if (!currentOnCall || currentOnCall.length === 0) {
    return (
      <div className="h-full flex flex-col items-center justify-center p-4 text-center">
        <Calendar className="text-muted-foreground mb-2" size={32} />
        <p className="text-sm text-muted-foreground">No on-call schedules configured</p>
        <Link
          to="/oncall"
          className="text-xs text-primary hover:underline mt-2 flex items-center gap-1"
        >
          Set up schedules <ChevronRight size={12} />
        </Link>
      </div>
    )
  }

  return (
    <div className="h-full flex flex-col p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-medium flex items-center gap-2">
          <UserCheck size={16} className="text-green-400" />
          On-Call Now
        </h3>
        <Link
          to="/oncall"
          className="text-xs text-primary hover:underline flex items-center gap-1"
        >
          Manage <ChevronRight size={12} />
        </Link>
      </div>

      <div className="flex-1 space-y-3 overflow-y-auto">
        {currentOnCall.map((schedule) => (
          <div
            key={schedule.schedule_id}
            className={cn(
              'p-3 rounded-lg border',
              schedule.is_override
                ? 'bg-yellow-500/10 border-yellow-500/30'
                : 'bg-muted/50 border-border'
            )}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium">{schedule.schedule_name}</span>
              {schedule.is_override && (
                <span className="px-2 py-0.5 bg-yellow-500/20 text-yellow-400 text-xs rounded flex items-center gap-1">
                  <AlertTriangle size={10} />
                  Override
                </span>
              )}
            </div>

            {schedule.primary && (
              <div className="flex items-center gap-2 mb-2">
                <div className="w-8 h-8 rounded-full bg-green-500/20 flex items-center justify-center">
                  <UserCheck className="text-green-400" size={16} />
                </div>
                <div>
                  <p className="text-sm font-medium">
                    {schedule.primary.user_name || schedule.primary.user_email}
                  </p>
                  <p className="text-xs text-muted-foreground">Primary</p>
                </div>
              </div>
            )}

            {config?.showBackup !== false && schedule.backup && (
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-full bg-blue-500/20 flex items-center justify-center">
                  <Users className="text-blue-400" size={16} />
                </div>
                <div>
                  <p className="text-sm font-medium">
                    {schedule.backup.user_name || schedule.backup.user_email}
                  </p>
                  <p className="text-xs text-muted-foreground">Backup</p>
                </div>
              </div>
            )}

            {schedule.is_override && schedule.override_end && (
              <div className="mt-2 pt-2 border-t border-yellow-500/30">
                <p className="text-xs text-muted-foreground flex items-center gap-1">
                  <Clock size={10} />
                  Override ends: {new Date(schedule.override_end).toLocaleString()}
                </p>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
