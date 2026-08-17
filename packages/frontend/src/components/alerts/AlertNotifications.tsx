import { useState, useEffect, useCallback } from 'react'
import { Bell, X, AlertTriangle, AlertCircle, Info, ExternalLink } from 'lucide-react'
import { Link } from 'react-router-dom'
import { useAlertWebSocket, AlertNotification } from '../../hooks/useWebSocket'
import { cn } from '../../lib/utils'
import PantherLogo from '../common/PantherLogo'

const severityConfig = {
  CRITICAL: {
    icon: AlertTriangle,
    bgColor: 'bg-red-500/20',
    textColor: 'text-red-400',
    borderColor: 'border-red-500/50',
  },
  HIGH: {
    icon: AlertTriangle,
    bgColor: 'bg-orange-500/20',
    textColor: 'text-orange-400',
    borderColor: 'border-orange-500/50',
  },
  MEDIUM: {
    icon: AlertCircle,
    bgColor: 'bg-yellow-500/20',
    textColor: 'text-yellow-400',
    borderColor: 'border-yellow-500/50',
  },
  LOW: {
    icon: Info,
    bgColor: 'bg-blue-500/20',
    textColor: 'text-blue-400',
    borderColor: 'border-blue-500/50',
  },
  INFO: {
    icon: Info,
    bgColor: 'bg-gray-500/20',
    textColor: 'text-gray-400',
    borderColor: 'border-gray-500/50',
  },
}

const toastIcon = (file: string, alt: string) => (
  <img src={`/icons/${file}`} alt={alt} className="w-full h-full object-contain rounded" />
)

const sourceIcons: Record<string, React.ReactNode> = {
  panther: <PantherLogo size={16} />,
  google_secops: toastIcon('google-cloud.png', 'Google SecOps'),
  splunk: toastIcon('splunk.png', 'Splunk'),
  sentinel: toastIcon('azure.png', 'Sentinel'),
  elastic: toastIcon('elastic.png', 'Elastic'),
  sumo_logic: toastIcon('sumologic.png', 'Sumo Logic'),
  crowdstrike_falcon: toastIcon('crowdstrike.png', 'CrowdStrike'),
  sentinelone: toastIcon('sentinelone.png', 'SentinelOne'),
  microsoft_defender: toastIcon('microsoft.png', 'Microsoft Defender'),
  carbon_black: toastIcon('carbonblack.png', 'Carbon Black'),
  falco: toastIcon('falco.png', 'Falco'),
  cortex_xdr: toastIcon('paloalto.png', 'Cortex XDR'),
  trend_vision_one: toastIcon('trendmicro.png', 'Trend Vision One'),
  aws_security_hub: toastIcon('aws.png', 'AWS Security Hub'),
  aws_guardduty: toastIcon('aws.png', 'AWS GuardDuty'),
  gcp_scc: toastIcon('google-cloud.png', 'GCP Security Command Center'),
  azure_defender: toastIcon('azure.png', 'Azure Defender'),
  wiz: toastIcon('wiz.png', 'Wiz'),
  orca: toastIcon('orca.png', 'Orca'),
  prowler: toastIcon('prowler.png', 'Prowler'),
  okta: toastIcon('okta.png', 'Okta'),
  entra_id: toastIcon('microsoft.png', 'Microsoft Entra ID'),
  azure_ad_identity: toastIcon('microsoft.png', 'Azure AD Identity'),
  crowdstrike_identity: toastIcon('crowdstrike.png', 'CrowdStrike Identity'),
  proofpoint: toastIcon('proofpoint.png', 'Proofpoint'),
  mimecast: toastIcon('mimecast.png', 'Mimecast'),
  microsoft_defender_email: toastIcon('microsoft.png', 'Defender for Office 365'),
  cloudflare: toastIcon('cloudflare-v2.png', 'Cloudflare'),
  darktrace: toastIcon('darktrace.png', 'Darktrace'),
  vectra: toastIcon('vectra.png', 'Vectra'),
  unifi: toastIcon('ubiquiti.png', 'UniFi Network'),
  unifi_api: toastIcon('ubiquiti.png', 'UniFi Network'),
  unifi_syslog: toastIcon('ubiquiti.png', 'UniFi Network'),
}

interface Toast {
  id: string
  alert: AlertNotification
  timestamp: number
}

export default function AlertNotifications() {
  const [toasts, setToasts] = useState<Toast[]>([])
  const [unreadCount, setUnreadCount] = useState(0)
  const [showDropdown, setShowDropdown] = useState(false)
  const [recentAlerts, setRecentAlerts] = useState<AlertNotification[]>([])

  const handleNewAlert = useCallback((alert: AlertNotification) => {
    // Add to toasts for popup notification
    const toast: Toast = {
      id: `${alert.id}-${Date.now()}`,
      alert,
      timestamp: Date.now(),
    }
    setToasts((prev) => [...prev, toast])

    // Add to recent alerts
    setRecentAlerts((prev) => {
      const updated = [alert, ...prev.filter((a) => a.id !== alert.id)]
      return updated.slice(0, 20) // Keep only last 20
    })

    // Increment unread count
    setUnreadCount((prev) => prev + 1)

    // Play notification sound for critical/high severity
    if (['CRITICAL', 'HIGH'].includes(alert.severity)) {
      try {
        const audio = new Audio('/notification.mp3')
        audio.volume = 0.3
        audio.play().catch(() => {})
      } catch {
        // Ignore audio errors
      }
    }
  }, [])

  const { isConnected } = useAlertWebSocket(handleNewAlert)

  // Auto-dismiss toasts after 5 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      const now = Date.now()
      setToasts((prev) => prev.filter((t) => now - t.timestamp < 5000))
    }, 1000)

    return () => clearInterval(interval)
  }, [])

  const dismissToast = (id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }

  const clearUnread = () => {
    setUnreadCount(0)
  }

  const getSeverityConfig = (severity: string) => {
    return severityConfig[severity as keyof typeof severityConfig] || severityConfig.INFO
  }

  return (
    <>
      {/* Notification Bell */}
      <div className="relative">
        <button
          onClick={() => {
            setShowDropdown(!showDropdown)
            if (!showDropdown) clearUnread()
          }}
          className={cn(
            "relative p-2 rounded-md transition-colors",
            isConnected ? "hover:bg-accent" : "opacity-50 cursor-not-allowed"
          )}
          title={isConnected ? "Alert notifications" : "Connecting..."}
        >
          <Bell size={20} className={isConnected ? "" : "animate-pulse"} />
          {unreadCount > 0 && (
            <span className="absolute -top-1 -right-1 min-w-[18px] h-[18px] flex items-center justify-center text-xs font-bold bg-red-500 text-white rounded-full px-1">
              {unreadCount > 99 ? "99+" : unreadCount}
            </span>
          )}
        </button>

        {/* Dropdown */}
        {showDropdown && (
          <>
            <div
              className="fixed inset-0 z-40"
              onClick={() => setShowDropdown(false)}
            />
            <div className="absolute right-0 top-full mt-2 w-96 max-h-96 overflow-auto rounded-lg border bg-background shadow-lg z-50">
              <div className="sticky top-0 flex items-center justify-between p-3 border-b bg-background">
                <h3 className="font-semibold">Recent Alerts</h3>
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <span className={cn(
                    "w-2 h-2 rounded-full",
                    isConnected ? "bg-green-500" : "bg-red-500"
                  )} />
                  {isConnected ? "Live" : "Disconnected"}
                </div>
              </div>

              {recentAlerts.length === 0 ? (
                <div className="p-6 text-center text-muted-foreground">
                  <Bell size={32} className="mx-auto mb-2 opacity-20" />
                  <p className="text-sm">No recent alerts</p>
                </div>
              ) : (
                <div className="divide-y">
                  {recentAlerts.map((alert) => {
                    const config = getSeverityConfig(alert.severity)
                    const Icon = config.icon
                    return (
                      <Link
                        key={alert.id}
                        to={`/alerts/${alert.id}`}
                        className="flex gap-3 p-3 hover:bg-muted/50 transition-colors"
                        onClick={() => setShowDropdown(false)}
                      >
                        <div className={cn("p-1.5 rounded flex items-center justify-center w-8 h-8", config.bgColor)}>
                          {alert.sourceType && sourceIcons[alert.sourceType] ? (
                            <div className="w-5 h-5 flex items-center justify-center">
                              {sourceIcons[alert.sourceType]}
                            </div>
                          ) : (
                            <Icon size={16} className={config.textColor} />
                          )}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-start justify-between gap-2">
                            <p className="font-medium text-sm truncate">{alert.title}</p>
                            <span className={cn(
                              "text-xs font-medium px-1.5 py-0.5 rounded shrink-0",
                              config.bgColor,
                              config.textColor
                            )}>
                              {alert.severity}
                            </span>
                          </div>
                          {alert.ruleName && (
                            <p className="text-xs text-muted-foreground truncate mt-0.5">
                              {alert.ruleName}
                            </p>
                          )}
                          <p className="text-xs text-muted-foreground mt-1">
                            {new Date(alert.createdAt).toLocaleString()}
                          </p>
                        </div>
                      </Link>
                    )
                  })}
                </div>
              )}

              <div className="sticky bottom-0 p-2 border-t bg-background">
                <Link
                  to="/alerts"
                  className="flex items-center justify-center gap-1 w-full py-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
                  onClick={() => setShowDropdown(false)}
                >
                  View all alerts
                  <ExternalLink size={14} />
                </Link>
              </div>
            </div>
          </>
        )}
      </div>

      {/* Toast Notifications */}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm">
        {toasts.map((toast) => {
          const config = getSeverityConfig(toast.alert.severity)
          const Icon = config.icon
          return (
            <div
              key={toast.id}
              className={cn(
                "flex items-start gap-3 p-4 rounded-lg border shadow-lg bg-background animate-in slide-in-from-right-5 fade-in duration-300",
                config.borderColor
              )}
            >
              <div className={cn("p-1.5 rounded shrink-0 flex items-center justify-center w-8 h-8", config.bgColor)}>
                {toast.alert.sourceType && sourceIcons[toast.alert.sourceType] ? (
                  <div className="w-5 h-5 flex items-center justify-center">
                    {sourceIcons[toast.alert.sourceType]}
                  </div>
                ) : (
                  <Icon size={16} className={config.textColor} />
                )}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-sm">{toast.alert.title}</p>
                    {toast.alert.ruleName && (
                      <p className="text-xs text-muted-foreground mt-0.5 truncate">
                        {toast.alert.ruleName}
                      </p>
                    )}
                  </div>
                  <button
                    onClick={() => dismissToast(toast.id)}
                    className="p-1 hover:bg-accent rounded shrink-0"
                  >
                    <X size={14} />
                  </button>
                </div>
                <Link
                  to={`/alerts/${toast.alert.id}`}
                  className="text-xs text-primary hover:underline mt-1 inline-block"
                  onClick={() => dismissToast(toast.id)}
                >
                  View details
                </Link>
              </div>
            </div>
          )
        })}
      </div>
    </>
  )
}
