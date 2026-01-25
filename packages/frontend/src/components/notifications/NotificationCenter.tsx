import { useState, useRef, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
  Bell,
  Check,
  CheckCheck,
  Trash2,
  AtSign,
  AlertTriangle,
  Clock,
  Play,
  XCircle,
  MessageSquare,
  User,
} from 'lucide-react'
import {
  useListNotificationsQuery,
  useGetUnreadCountQuery,
  useMarkNotificationAsReadMutation,
  useMarkAllNotificationsAsReadMutation,
  useDeleteNotificationMutation,
  useClearNotificationsMutation,
  type NotificationResponse,
  type NotificationType,
} from '../../api/pantherApi'
import { cn } from '../../lib/utils'

export default function NotificationCenter() {
  const [isOpen, setIsOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)

  const { data: unreadData } = useGetUnreadCountQuery(undefined, {
    pollingInterval: 30000, // Poll every 30 seconds
  })
  const { data: notifications, isLoading } = useListNotificationsQuery(
    { pageSize: 20 },
    { skip: !isOpen }
  )
  const [markAsRead] = useMarkNotificationAsReadMutation()
  const [markAllAsRead] = useMarkAllNotificationsAsReadMutation()
  const [deleteNotification] = useDeleteNotificationMutation()
  const [clearNotifications] = useClearNotificationsMutation()

  const unreadCount = unreadData?.unread_count || 0

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const handleMarkAsRead = async (id: string) => {
    try {
      await markAsRead(id).unwrap()
    } catch (error) {
      console.error('Failed to mark as read:', error)
    }
  }

  const handleMarkAllAsRead = async () => {
    try {
      await markAllAsRead().unwrap()
    } catch (error) {
      console.error('Failed to mark all as read:', error)
    }
  }

  const handleDelete = async (id: string) => {
    try {
      await deleteNotification(id).unwrap()
    } catch (error) {
      console.error('Failed to delete notification:', error)
    }
  }

  const handleClearRead = async () => {
    try {
      await clearNotifications({ readOnly: true }).unwrap()
    } catch (error) {
      console.error('Failed to clear notifications:', error)
    }
  }

  const getNotificationIcon = (type: NotificationType) => {
    switch (type) {
      case 'mention':
        return <AtSign className="w-4 h-4 text-blue-500" />
      case 'alert_assigned':
        return <AlertTriangle className="w-4 h-4 text-orange-500" />
      case 'incident_assigned':
      case 'case_assigned':
        return <User className="w-4 h-4 text-purple-500" />
      case 'comment_reply':
        return <MessageSquare className="w-4 h-4 text-green-500" />
      case 'sla_warning':
        return <Clock className="w-4 h-4 text-yellow-500" />
      case 'sla_breach':
        return <Clock className="w-4 h-4 text-red-500" />
      case 'playbook_completed':
        return <Play className="w-4 h-4 text-green-500" />
      case 'playbook_failed':
        return <XCircle className="w-4 h-4 text-red-500" />
      default:
        return <Bell className="w-4 h-4 text-gray-500" />
    }
  }

  const getResourceLink = (notification: NotificationResponse) => {
    if (!notification.resource_type || !notification.resource_id) return null

    switch (notification.resource_type) {
      case 'alert':
        return `/alerts/${notification.resource_id}`
      case 'incident':
        return `/incidents/${notification.resource_id}`
      case 'case':
        return `/cases/${notification.resource_id}`
      case 'rule':
        return `/rules/${notification.resource_id}`
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

    if (diffMins < 1) return 'just now'
    if (diffMins < 60) return `${diffMins}m ago`
    if (diffHours < 24) return `${diffHours}h ago`
    if (diffDays < 7) return `${diffDays}d ago`
    return date.toLocaleDateString()
  }

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="relative p-2 hover:bg-accent rounded-md transition-colors"
        title="Notifications"
      >
        <Bell className="w-5 h-5" />
        {unreadCount > 0 && (
          <span className="absolute top-0 right-0 w-5 h-5 bg-red-500 text-white text-xs rounded-full flex items-center justify-center">
            {unreadCount > 9 ? '9+' : unreadCount}
          </span>
        )}
      </button>

      {isOpen && (
        <div className="absolute right-0 mt-2 w-96 bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 z-50 max-h-[80vh] overflow-hidden">
          {/* Header */}
          <div className="p-4 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold text-gray-900 dark:text-white">Notifications</h3>
              {notifications && notifications.unread_count > 0 && (
                <button
                  onClick={handleMarkAllAsRead}
                  className="flex items-center gap-1 text-sm text-blue-600 hover:text-blue-700"
                >
                  <CheckCheck className="w-4 h-4" />
                  Mark all read
                </button>
              )}
            </div>
          </div>

          {/* Notifications list */}
          <div className="overflow-y-auto max-h-96">
            {isLoading ? (
              <div className="p-4 text-center">
                <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500 mx-auto" />
              </div>
            ) : notifications && notifications.items.length > 0 ? (
              <div className="divide-y divide-gray-200 dark:divide-gray-700">
                {notifications.items.map((notification) => {
                  const link = getResourceLink(notification)
                  const content = (
                    <div
                      className={cn(
                        'p-4 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors',
                        !notification.is_read && 'bg-blue-50/50 dark:bg-blue-900/10'
                      )}
                    >
                      <div className="flex gap-3">
                        <div className="flex-shrink-0 mt-1">
                          {getNotificationIcon(notification.notification_type)}
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-gray-900 dark:text-white">
                            {notification.title}
                          </p>
                          <p className="text-sm text-gray-600 dark:text-gray-400 line-clamp-2">
                            {notification.message}
                          </p>
                          <div className="flex items-center gap-2 mt-1">
                            <span className="text-xs text-gray-500">
                              {formatDate(notification.created_at)}
                            </span>
                            {notification.created_by && (
                              <span className="text-xs text-gray-500">
                                from {notification.created_by}
                              </span>
                            )}
                          </div>
                        </div>
                        <div className="flex-shrink-0 flex items-start gap-1">
                          {!notification.is_read && (
                            <button
                              onClick={(e) => {
                                e.preventDefault()
                                e.stopPropagation()
                                handleMarkAsRead(notification.id)
                              }}
                              className="p-1 text-gray-400 hover:text-green-600"
                              title="Mark as read"
                            >
                              <Check className="w-4 h-4" />
                            </button>
                          )}
                          <button
                            onClick={(e) => {
                              e.preventDefault()
                              e.stopPropagation()
                              handleDelete(notification.id)
                            }}
                            className="p-1 text-gray-400 hover:text-red-600"
                            title="Delete"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    </div>
                  )

                  if (link) {
                    return (
                      <Link
                        key={notification.id}
                        to={link}
                        onClick={() => {
                          if (!notification.is_read) {
                            handleMarkAsRead(notification.id)
                          }
                          setIsOpen(false)
                        }}
                      >
                        {content}
                      </Link>
                    )
                  }

                  return <div key={notification.id}>{content}</div>
                })}
              </div>
            ) : (
              <div className="p-8 text-center text-gray-500 dark:text-gray-400">
                <Bell className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p>No notifications</p>
              </div>
            )}
          </div>

          {/* Footer */}
          {notifications && notifications.items.length > 0 && (
            <div className="p-3 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/30">
              <button
                onClick={handleClearRead}
                className="w-full text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
              >
                Clear read notifications
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
