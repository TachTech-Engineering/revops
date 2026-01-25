import { useState, useEffect } from 'react'
import { Settings, Moon, Sun, Bell, Keyboard, Save, Check } from 'lucide-react'
import { useGetSettingsQuery, useUpdateSettingsMutation } from '../api/pantherApi'

export default function SettingsPage() {
  const { data: settings, isLoading } = useGetSettingsQuery()
  const [updateSettings, { isLoading: isSaving }] = useUpdateSettingsMutation()
  const [saved, setSaved] = useState(false)

  const [localSettings, setLocalSettings] = useState({
    theme: 'dark',
    default_time_range: 7,
    alerts_per_page: 50,
    notifications_enabled: true,
    notification_severities: ['CRITICAL', 'HIGH'],
    keyboard_shortcuts_enabled: true,
  })

  useEffect(() => {
    if (settings) {
      setLocalSettings({
        theme: settings.theme,
        default_time_range: settings.default_time_range,
        alerts_per_page: settings.alerts_per_page,
        notifications_enabled: settings.notifications_enabled,
        notification_severities: settings.notification_severities,
        keyboard_shortcuts_enabled: settings.keyboard_shortcuts_enabled,
      })
    }
  }, [settings])

  const handleSave = async () => {
    await updateSettings(localSettings)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)

    // Apply theme immediately
    if (localSettings.theme === 'light') {
      document.documentElement.classList.remove('dark')
    } else {
      document.documentElement.classList.add('dark')
    }
  }

  const toggleSeverity = (severity: string) => {
    setLocalSettings((prev) => ({
      ...prev,
      notification_severities: prev.notification_severities.includes(severity)
        ? prev.notification_severities.filter((s) => s !== severity)
        : [...prev.notification_severities, severity],
    }))
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h1 className="text-3xl font-bold">Settings</h1>
        <p className="text-muted-foreground">Configure your dashboard preferences</p>
      </div>

      {/* Appearance */}
      <div className="rounded-lg border bg-background p-6">
        <h3 className="font-semibold mb-4 flex items-center gap-2">
          {localSettings.theme === 'dark' ? <Moon size={18} /> : <Sun size={18} />}
          Appearance
        </h3>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">Theme</label>
            <div className="flex gap-2">
              <button
                onClick={() => setLocalSettings((p) => ({ ...p, theme: 'dark' }))}
                className={`flex items-center gap-2 px-4 py-2 rounded border ${
                  localSettings.theme === 'dark'
                    ? 'bg-primary text-primary-foreground border-primary'
                    : 'hover:bg-accent'
                }`}
              >
                <Moon size={16} />
                Dark
              </button>
              <button
                onClick={() => setLocalSettings((p) => ({ ...p, theme: 'light' }))}
                className={`flex items-center gap-2 px-4 py-2 rounded border ${
                  localSettings.theme === 'light'
                    ? 'bg-primary text-primary-foreground border-primary'
                    : 'hover:bg-accent'
                }`}
              >
                <Sun size={16} />
                Light
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Alerts */}
      <div className="rounded-lg border bg-background p-6">
        <h3 className="font-semibold mb-4 flex items-center gap-2">
          <Settings size={18} />
          Alerts
        </h3>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">Default Time Range</label>
            <select
              value={localSettings.default_time_range}
              onChange={(e) =>
                setLocalSettings((p) => ({ ...p, default_time_range: Number(e.target.value) }))
              }
              className="rounded-md border bg-background px-3 py-2 text-sm"
            >
              <option value={1}>Last 24 hours</option>
              <option value={7}>Last 7 days</option>
              <option value={14}>Last 14 days</option>
              <option value={30}>Last 30 days</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium mb-2">Alerts Per Page</label>
            <select
              value={localSettings.alerts_per_page}
              onChange={(e) =>
                setLocalSettings((p) => ({ ...p, alerts_per_page: Number(e.target.value) }))
              }
              className="rounded-md border bg-background px-3 py-2 text-sm"
            >
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </div>
        </div>
      </div>

      {/* Notifications */}
      <div className="rounded-lg border bg-background p-6">
        <h3 className="font-semibold mb-4 flex items-center gap-2">
          <Bell size={18} />
          Notifications
        </h3>

        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">Enable Notifications</p>
              <p className="text-sm text-muted-foreground">
                Show notification bell for new alerts
              </p>
            </div>
            <button
              onClick={() =>
                setLocalSettings((p) => ({
                  ...p,
                  notifications_enabled: !p.notifications_enabled,
                }))
              }
              className={`w-12 h-6 rounded-full transition-colors ${
                localSettings.notifications_enabled ? 'bg-primary' : 'bg-muted'
              }`}
            >
              <div
                className={`w-5 h-5 rounded-full bg-white transition-transform ${
                  localSettings.notifications_enabled ? 'translate-x-6' : 'translate-x-0.5'
                }`}
              />
            </button>
          </div>

          {localSettings.notifications_enabled && (
            <div>
              <label className="block text-sm font-medium mb-2">
                Notify for Severities
              </label>
              <div className="flex flex-wrap gap-2">
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((severity) => (
                  <button
                    key={severity}
                    onClick={() => toggleSeverity(severity)}
                    className={`px-3 py-1 rounded text-sm ${
                      localSettings.notification_severities.includes(severity)
                        ? severity === 'CRITICAL'
                          ? 'bg-red-500/20 text-red-400 border border-red-500'
                          : severity === 'HIGH'
                          ? 'bg-orange-500/20 text-orange-400 border border-orange-500'
                          : severity === 'MEDIUM'
                          ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500'
                          : severity === 'LOW'
                          ? 'bg-green-500/20 text-green-400 border border-green-500'
                          : 'bg-blue-500/20 text-blue-400 border border-blue-500'
                        : 'bg-muted hover:bg-accent'
                    }`}
                  >
                    {severity}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Keyboard Shortcuts */}
      <div className="rounded-lg border bg-background p-6">
        <h3 className="font-semibold mb-4 flex items-center gap-2">
          <Keyboard size={18} />
          Keyboard Shortcuts
        </h3>

        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">Enable Keyboard Shortcuts</p>
              <p className="text-sm text-muted-foreground">
                Use keyboard shortcuts for quick navigation
              </p>
            </div>
            <button
              onClick={() =>
                setLocalSettings((p) => ({
                  ...p,
                  keyboard_shortcuts_enabled: !p.keyboard_shortcuts_enabled,
                }))
              }
              className={`w-12 h-6 rounded-full transition-colors ${
                localSettings.keyboard_shortcuts_enabled ? 'bg-primary' : 'bg-muted'
              }`}
            >
              <div
                className={`w-5 h-5 rounded-full bg-white transition-transform ${
                  localSettings.keyboard_shortcuts_enabled ? 'translate-x-6' : 'translate-x-0.5'
                }`}
              />
            </button>
          </div>

          {localSettings.keyboard_shortcuts_enabled && (
            <div className="text-sm space-y-2">
              <p className="text-muted-foreground mb-2">Available shortcuts:</p>
              <div className="grid grid-cols-2 gap-2">
                <div className="flex items-center gap-2">
                  <kbd className="px-2 py-1 bg-muted rounded text-xs">g a</kbd>
                  <span>Go to Alerts</span>
                </div>
                <div className="flex items-center gap-2">
                  <kbd className="px-2 py-1 bg-muted rounded text-xs">g r</kbd>
                  <span>Go to Rules</span>
                </div>
                <div className="flex items-center gap-2">
                  <kbd className="px-2 py-1 bg-muted rounded text-xs">g q</kbd>
                  <span>Go to Queries</span>
                </div>
                <div className="flex items-center gap-2">
                  <kbd className="px-2 py-1 bg-muted rounded text-xs">g s</kbd>
                  <span>Go to Settings</span>
                </div>
                <div className="flex items-center gap-2">
                  <kbd className="px-2 py-1 bg-muted rounded text-xs">/</kbd>
                  <span>Focus search</span>
                </div>
                <div className="flex items-center gap-2">
                  <kbd className="px-2 py-1 bg-muted rounded text-xs">?</kbd>
                  <span>Show shortcuts</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Save Button */}
      <div className="flex justify-end">
        <button
          onClick={handleSave}
          disabled={isSaving}
          className="flex items-center gap-2 px-6 py-2 bg-primary text-primary-foreground rounded-md font-medium hover:bg-primary/90 disabled:opacity-50"
        >
          {saved ? (
            <>
              <Check size={18} />
              Saved!
            </>
          ) : (
            <>
              <Save size={18} />
              {isSaving ? 'Saving...' : 'Save Settings'}
            </>
          )}
        </button>
      </div>
    </div>
  )
}
