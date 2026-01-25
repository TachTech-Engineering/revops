import { useState, useRef, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, CheckCircle, Clock, User } from 'lucide-react'
import { cn } from '../../lib/utils'

interface Alert {
  id: string
  title: string
  severity: string
  status: string
  creationTime: string
  ruleName?: string
  assignee?: string
}

interface SwipeableAlertCardProps {
  alert: Alert
  onAcknowledge?: (id: string) => void
  onAssign?: (id: string) => void
  onResolve?: (id: string) => void
}

export default function SwipeableAlertCard({
  alert,
  onAcknowledge,
  onAssign,
  onResolve,
}: SwipeableAlertCardProps) {
  const [swipeX, setSwipeX] = useState(0)
  const [isDragging, setIsDragging] = useState(false)
  const startX = useRef(0)
  const cardRef = useRef<HTMLDivElement>(null)

  const SWIPE_THRESHOLD = 100
  const MAX_SWIPE = 150

  const handleTouchStart = (e: React.TouchEvent) => {
    startX.current = e.touches[0].clientX
    setIsDragging(true)
  }

  const handleTouchMove = (e: React.TouchEvent) => {
    if (!isDragging) return
    const currentX = e.touches[0].clientX
    const diff = currentX - startX.current
    // Only allow swipe right (positive values)
    setSwipeX(Math.min(Math.max(0, diff), MAX_SWIPE))
  }

  const handleTouchEnd = () => {
    setIsDragging(false)
    if (swipeX > SWIPE_THRESHOLD) {
      // Trigger action
      if (alert.status === 'OPEN' && onAcknowledge) {
        onAcknowledge(alert.id)
      } else if (onResolve) {
        onResolve(alert.id)
      }
    }
    setSwipeX(0)
  }

  // Reset swipe on mouse leave
  useEffect(() => {
    const handleMouseUp = () => {
      if (isDragging) {
        setIsDragging(false)
        setSwipeX(0)
      }
    }
    window.addEventListener('mouseup', handleMouseUp)
    return () => window.removeEventListener('mouseup', handleMouseUp)
  }, [isDragging])

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'border-l-red-500 bg-red-50 dark:bg-red-900/10'
      case 'HIGH':
        return 'border-l-orange-500 bg-orange-50 dark:bg-orange-900/10'
      case 'MEDIUM':
        return 'border-l-yellow-500 bg-yellow-50 dark:bg-yellow-900/10'
      case 'LOW':
        return 'border-l-blue-500 bg-blue-50 dark:bg-blue-900/10'
      default:
        return 'border-l-gray-500 bg-gray-50 dark:bg-gray-800'
    }
  }

  const getSeverityBadgeColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300'
      case 'HIGH':
        return 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300'
      case 'MEDIUM':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300'
      case 'LOW':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300'
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'OPEN':
        return <AlertTriangle className="w-4 h-4 text-red-500" />
      case 'TRIAGED':
        return <Clock className="w-4 h-4 text-yellow-500" />
      case 'RESOLVED':
      case 'CLOSED':
        return <CheckCircle className="w-4 h-4 text-green-500" />
      default:
        return null
    }
  }

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffMins = Math.floor(diffMs / 60000)
    const diffHours = Math.floor(diffMins / 60)
    const diffDays = Math.floor(diffHours / 24)

    if (diffMins < 60) return `${diffMins}m ago`
    if (diffHours < 24) return `${diffHours}h ago`
    return `${diffDays}d ago`
  }

  const actionLabel = alert.status === 'OPEN' ? 'Acknowledge' : 'Resolve'
  const swipeProgress = swipeX / MAX_SWIPE

  return (
    <div className="relative overflow-hidden rounded-lg mb-3">
      {/* Background action indicator */}
      <div
        className={cn(
          'absolute inset-y-0 left-0 flex items-center justify-start pl-4 transition-colors',
          swipeX > SWIPE_THRESHOLD ? 'bg-green-500' : 'bg-green-400'
        )}
        style={{ width: `${swipeX}px` }}
      >
        <span
          className="text-white font-medium text-sm"
          style={{ opacity: swipeProgress }}
        >
          {actionLabel}
        </span>
      </div>

      {/* Card content */}
      <div
        ref={cardRef}
        onTouchStart={handleTouchStart}
        onTouchMove={handleTouchMove}
        onTouchEnd={handleTouchEnd}
        className={cn(
          'relative border-l-4 rounded-lg p-4 transition-transform',
          getSeverityColor(alert.severity)
        )}
        style={{ transform: `translateX(${swipeX}px)` }}
      >
        <Link to={`/alerts/${alert.id}`} className="block">
          {/* Header */}
          <div className="flex items-start justify-between mb-2">
            <div className="flex items-center gap-2">
              {getStatusIcon(alert.status)}
              <span
                className={cn(
                  'px-2 py-0.5 rounded-full text-xs font-medium',
                  getSeverityBadgeColor(alert.severity)
                )}
              >
                {alert.severity}
              </span>
            </div>
            <span className="text-xs text-gray-500">{formatDate(alert.creationTime)}</span>
          </div>

          {/* Title */}
          <h3 className="text-sm font-medium text-gray-900 dark:text-white line-clamp-2 mb-2">
            {alert.title}
          </h3>

          {/* Footer */}
          <div className="flex items-center justify-between text-xs text-gray-500">
            {alert.ruleName && (
              <span className="truncate max-w-[60%]">{alert.ruleName}</span>
            )}
            {alert.assignee && (
              <div className="flex items-center gap-1">
                <User className="w-3 h-3" />
                <span>{alert.assignee}</span>
              </div>
            )}
          </div>
        </Link>

        {/* Swipe hint on mobile */}
        <div className="md:hidden mt-3 pt-3 border-t border-gray-200 dark:border-gray-700">
          <p className="text-xs text-gray-400 text-center">
            Swipe right to {actionLabel.toLowerCase()}
          </p>
        </div>
      </div>
    </div>
  )
}

// Mobile-optimized alert list
export function MobileAlertList({
  alerts,
  onAcknowledge,
  onResolve,
}: {
  alerts: Alert[]
  onAcknowledge?: (id: string) => void
  onResolve?: (id: string) => void
}) {
  if (alerts.length === 0) {
    return (
      <div className="text-center py-8 text-gray-500 dark:text-gray-400">
        <AlertTriangle className="w-12 h-12 mx-auto mb-3 opacity-50" />
        <p>No alerts to display</p>
      </div>
    )
  }

  return (
    <div className="space-y-2">
      {alerts.map((alert) => (
        <SwipeableAlertCard
          key={alert.id}
          alert={alert}
          onAcknowledge={onAcknowledge}
          onResolve={onResolve}
        />
      ))}
    </div>
  )
}

// Pull to refresh component
export function PullToRefresh({
  onRefresh,
  children,
}: {
  onRefresh: () => Promise<void>
  children: React.ReactNode
}) {
  const [isPulling, setIsPulling] = useState(false)
  const [pullDistance, setPullDistance] = useState(0)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)
  const startY = useRef(0)

  const PULL_THRESHOLD = 80

  const handleTouchStart = (e: React.TouchEvent) => {
    if (containerRef.current?.scrollTop === 0) {
      startY.current = e.touches[0].clientY
      setIsPulling(true)
    }
  }

  const handleTouchMove = (e: React.TouchEvent) => {
    if (!isPulling || isRefreshing) return
    const currentY = e.touches[0].clientY
    const diff = currentY - startY.current
    if (diff > 0) {
      setPullDistance(Math.min(diff * 0.5, 100))
    }
  }

  const handleTouchEnd = async () => {
    if (pullDistance > PULL_THRESHOLD && !isRefreshing) {
      setIsRefreshing(true)
      try {
        await onRefresh()
      } finally {
        setIsRefreshing(false)
      }
    }
    setIsPulling(false)
    setPullDistance(0)
  }

  return (
    <div
      ref={containerRef}
      className="relative"
      onTouchStart={handleTouchStart}
      onTouchMove={handleTouchMove}
      onTouchEnd={handleTouchEnd}
    >
      {/* Pull indicator */}
      <div
        className="absolute inset-x-0 top-0 flex items-center justify-center transition-transform overflow-hidden"
        style={{
          height: `${pullDistance}px`,
          transform: `translateY(${-pullDistance}px)`,
        }}
      >
        <div
          className={cn(
            'w-6 h-6 border-2 border-blue-500 rounded-full',
            isRefreshing ? 'animate-spin border-t-transparent' : ''
          )}
          style={{
            opacity: pullDistance / PULL_THRESHOLD,
            transform: `rotate(${pullDistance * 3}deg)`,
          }}
        />
      </div>

      {/* Content */}
      <div
        className="transition-transform"
        style={{ transform: `translateY(${pullDistance}px)` }}
      >
        {children}
      </div>
    </div>
  )
}
