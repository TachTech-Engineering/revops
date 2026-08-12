import { Link } from 'react-router-dom'
import {
  Trophy,
  RefreshCw,
  ChevronRight,
  CheckCircle,
  Clock,
  Target,
} from 'lucide-react'
import { cn } from '../../../lib/utils'

interface TopAnalystsWidgetProps {
  config?: {
    limit?: number
    period?: '7d' | '30d' | '90d'
  }
}

// Mock data - in production this would come from an API
const useTopAnalysts = (limit: number = 5) => {
  return {
    data: {
      analysts: [
        {
          id: '1',
          name: 'Alice Chen',
          email: 'alice@company.com',
          avatar: null,
          alerts_resolved: 142,
          avg_resolution_time_min: 18,
          accuracy: 98,
          rank_change: 0,
        },
        {
          id: '2',
          name: 'Bob Smith',
          email: 'bob@company.com',
          avatar: null,
          alerts_resolved: 128,
          avg_resolution_time_min: 22,
          accuracy: 95,
          rank_change: 2,
        },
        {
          id: '3',
          name: 'Carol Davis',
          email: 'carol@company.com',
          avatar: null,
          alerts_resolved: 115,
          avg_resolution_time_min: 15,
          accuracy: 97,
          rank_change: -1,
        },
        {
          id: '4',
          name: 'Dave Wilson',
          email: 'dave@company.com',
          avatar: null,
          alerts_resolved: 98,
          avg_resolution_time_min: 25,
          accuracy: 92,
          rank_change: 1,
        },
        {
          id: '5',
          name: 'Eve Johnson',
          email: 'eve@company.com',
          avatar: null,
          alerts_resolved: 87,
          avg_resolution_time_min: 20,
          accuracy: 94,
          rank_change: -2,
        },
      ].slice(0, limit),
      period: '30d',
    },
    isLoading: false,
  }
}

function getInitials(name: string): string {
  return name
    .split(' ')
    .map((n) => n[0])
    .join('')
    .toUpperCase()
}

const rankColors = ['text-yellow-400', 'text-gray-400', 'text-amber-600', 'text-muted-foreground']

export default function TopAnalystsWidget({ config }: TopAnalystsWidgetProps) {
  const { data, isLoading } = useTopAnalysts(config?.limit || 5)

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
          <Trophy size={16} className="text-yellow-400" />
          Top Analysts
        </h3>
        <Link
          to="/analytics"
          className="text-xs text-primary hover:underline flex items-center gap-1"
        >
          Leaderboard <ChevronRight size={12} />
        </Link>
      </div>

      {/* Analyst List */}
      <div className="flex-1 space-y-2 overflow-y-auto">
        {data.analysts.map((analyst, index) => (
          <div
            key={analyst.id}
            className={cn(
              'flex items-center gap-3 p-2 rounded-lg',
              index === 0 ? 'bg-yellow-500/10 border border-yellow-500/30' : 'bg-muted/30'
            )}
          >
            {/* Rank */}
            <div
              className={cn(
                'w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold',
                index < 3 ? 'bg-muted' : ''
              )}
            >
              <span className={rankColors[index] || rankColors[3]}>
                {index === 0 ? '🥇' : index === 1 ? '🥈' : index === 2 ? '🥉' : index + 1}
              </span>
            </div>

            {/* Avatar */}
            <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center text-xs font-medium">
              {getInitials(analyst.name)}
            </div>

            {/* Info */}
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium truncate">{analyst.name}</p>
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <span className="flex items-center gap-0.5">
                  <CheckCircle size={10} className="text-green-400" />
                  {analyst.alerts_resolved}
                </span>
                <span className="flex items-center gap-0.5">
                  <Clock size={10} />
                  {analyst.avg_resolution_time_min}m
                </span>
                <span className="flex items-center gap-0.5">
                  <Target size={10} />
                  {analyst.accuracy}%
                </span>
              </div>
            </div>

            {/* Rank Change */}
            {analyst.rank_change !== 0 && (
              <div
                className={cn(
                  'text-xs font-medium',
                  analyst.rank_change > 0 ? 'text-green-400' : 'text-red-400'
                )}
              >
                {analyst.rank_change > 0 ? `↑${analyst.rank_change}` : `↓${Math.abs(analyst.rank_change)}`}
              </div>
            )}
          </div>
        ))}
      </div>

      <p className="text-xs text-muted-foreground text-center mt-2">
        Last {data.period === '7d' ? '7 days' : data.period === '30d' ? '30 days' : '90 days'}
      </p>
    </div>
  )
}
