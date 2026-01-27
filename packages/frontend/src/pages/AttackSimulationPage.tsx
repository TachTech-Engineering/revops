import { useState } from 'react'
import {
  Zap,
  Play,
  RefreshCw,
  CheckCircle,
  XCircle,
  Clock,
  Cloud,
  Monitor,
  Filter,
  ChevronDown,
  ChevronUp,
  Target,
  Shield,
  Copy,
  Terminal,
  Search,
  Database,
  Check,
  AlertCircle,
} from 'lucide-react'
import {
  useListSimulationTemplatesQuery,
  useListSimulationRunsQuery,
  useRunSimulationMutation,
  useVerifySimulationDetectionMutation,
  useGetManualCommandsMutation,
  useMarkSimulationExecutedMutation,
  useGetSyncStatusQuery,
  useSyncTechniquesMutation,
  useGetSimulationStatsQuery,
  type SimulationTemplateResponse,
  type SimulationRunResponse,
  type ManualCommandsResponse,
} from '../api/pantherApi'
import { cn } from '../lib/utils'

const FRAMEWORK_TABS = [
  { value: '', label: 'All', icon: Zap },
  { value: 'atomic', label: 'Atomic Red Team', icon: Monitor },
  { value: 'stratus', label: 'Stratus Red Team', icon: Cloud },
]

const STATUS_COLORS: Record<string, { bg: string; text: string; icon: React.ElementType }> = {
  pending: { bg: 'bg-yellow-500/10', text: 'text-yellow-500', icon: Clock },
  running: { bg: 'bg-blue-500/10', text: 'text-blue-500', icon: RefreshCw },
  completed: { bg: 'bg-green-500/10', text: 'text-green-500', icon: CheckCircle },
  failed: { bg: 'bg-red-500/10', text: 'text-red-500', icon: XCircle },
  detected: { bg: 'bg-green-500/10', text: 'text-green-500', icon: Shield },
  not_detected: { bg: 'bg-orange-500/10', text: 'text-orange-500', icon: XCircle },
}

const MITRE_TACTICS = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Exfiltration',
  'Impact',
]

export default function AttackSimulationPage() {
  const [framework, setFramework] = useState('')
  const [tacticFilter, setTacticFilter] = useState('')
  const [platformFilter, setPlatformFilter] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [activeTab, setActiveTab] = useState<'templates' | 'history'>('templates')
  const [selectedTemplate, setSelectedTemplate] = useState<SimulationTemplateResponse | null>(null)
  const [showCommandModal, setShowCommandModal] = useState(false)
  const [commands, setCommands] = useState<ManualCommandsResponse | null>(null)

  const { data: templates, isLoading: isLoadingTemplates, refetch: refetchTemplates } = useListSimulationTemplatesQuery({
    framework: framework || undefined,
    search: searchQuery || undefined,
    page_size: 100,
  })
  const { data: runs, isLoading: isLoadingRuns, refetch: refetchRuns } = useListSimulationRunsQuery({})
  const { data: syncStatus, refetch: refetchSyncStatus } = useGetSyncStatusQuery()
  const { data: stats } = useGetSimulationStatsQuery()

  const [runSimulation, { isLoading: isRunning }] = useRunSimulationMutation()
  const [verifyDetection] = useVerifySimulationDetectionMutation()
  const [getManualCommands, { isLoading: isLoadingCommands }] = useGetManualCommandsMutation()
  const [markExecuted] = useMarkSimulationExecutedMutation()
  const [syncTechniques, { isLoading: isSyncing }] = useSyncTechniquesMutation()

  const filteredTemplates = templates?.items?.filter((t) => {
    if (tacticFilter && !t.mitre_tactic?.toLowerCase().includes(tacticFilter.toLowerCase())) return false
    if (platformFilter && !t.platforms.includes(platformFilter)) return false
    return true
  })

  const handleShowCommands = async (template: SimulationTemplateResponse) => {
    setSelectedTemplate(template)
    try {
      const result = await getManualCommands({ template_id: template.id }).unwrap()
      setCommands(result)
      setShowCommandModal(true)
    } catch (e) {
      alert('Failed to get commands')
    }
  }

  const handleRunSimulation = async (template: SimulationTemplateResponse) => {
    const target = template.framework === 'stratus'
      ? window.prompt('Enter cloud target (e.g., AWS account alias):')
      : window.prompt('Enter target hostname or IP:')

    if (!target) return

    try {
      await runSimulation({
        template_id: template.id,
        targets: [target],
        mode: 'manual',
      }).unwrap()
      refetchRuns()
      setActiveTab('history')
    } catch (e) {
      alert('Failed to start simulation')
    }
  }

  const handleVerifyDetection = async (runId: string) => {
    try {
      await verifyDetection(runId).unwrap()
      refetchRuns()
    } catch (e) {
      alert('Failed to verify detection')
    }
  }

  const handleMarkExecuted = async (runId: string) => {
    try {
      await markExecuted(runId).unwrap()
      refetchRuns()
    } catch (e) {
      alert('Failed to mark as executed')
    }
  }

  const handleSync = async () => {
    try {
      await syncTechniques({ force: true }).unwrap()
      refetchTemplates()
      refetchSyncStatus()
    } catch (e: unknown) {
      if ((e as { status?: number })?.status !== 304) {
        alert('Failed to sync techniques')
      }
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold flex items-center gap-2">
            <Zap size={24} />
            Attack Simulation
          </h1>
          <p className="text-muted-foreground mt-1">
            Test your detection capabilities with controlled attack simulations
          </p>
        </div>

        {/* Sync Status */}
        <div className="flex items-center gap-4">
          {stats && (
            <div className="text-sm text-muted-foreground">
              <span className="font-medium text-foreground">{stats.templates?.atomic_red_team || 0}</span> Atomic +{' '}
              <span className="font-medium text-foreground">{stats.templates?.stratus_red_team || 0}</span> Stratus templates
            </div>
          )}
          <div className="flex items-center gap-2">
            <Database size={14} className="text-muted-foreground" />
            <span className="text-xs text-muted-foreground">
              {syncStatus?.last_sync
                ? `Synced ${new Date(syncStatus.last_sync).toLocaleDateString()}`
                : 'Not synced'}
            </span>
            <button
              onClick={handleSync}
              disabled={isSyncing}
              className="flex items-center gap-1 px-2 py-1 text-xs bg-accent hover:bg-accent/80 rounded"
            >
              <RefreshCw size={12} className={isSyncing ? 'animate-spin' : ''} />
              Sync
            </button>
          </div>
        </div>
      </div>

      {/* Framework Tabs */}
      <div className="flex items-center gap-2 border-b">
        {FRAMEWORK_TABS.map((tab) => {
          const Icon = tab.icon
          return (
            <button
              key={tab.value}
              onClick={() => setFramework(tab.value)}
              className={cn(
                'flex items-center gap-2 px-4 py-2 border-b-2 transition-colors',
                framework === tab.value
                  ? 'border-primary text-foreground'
                  : 'border-transparent text-muted-foreground hover:text-foreground'
              )}
            >
              <Icon size={16} />
              {tab.label}
            </button>
          )
        })}
        <div className="flex-1" />
        <div className="flex gap-2 pb-2">
          <button
            onClick={() => setActiveTab('templates')}
            className={cn(
              'px-3 py-1 rounded-md text-sm',
              activeTab === 'templates' ? 'bg-primary text-primary-foreground' : 'bg-accent'
            )}
          >
            Templates
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={cn(
              'px-3 py-1 rounded-md text-sm',
              activeTab === 'history' ? 'bg-primary text-primary-foreground' : 'bg-accent'
            )}
          >
            Run History
          </button>
        </div>
      </div>

      {activeTab === 'templates' ? (
        <>
          {/* Filters */}
          <div className="flex items-center gap-4 flex-wrap">
            <div className="flex items-center gap-2 flex-1 max-w-md">
              <Search size={16} className="text-muted-foreground" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search techniques..."
                className="flex-1 px-3 py-1.5 bg-card border rounded-md text-sm"
              />
            </div>
            <div className="flex items-center gap-2">
              <Filter size={16} className="text-muted-foreground" />
              <span className="text-sm text-muted-foreground">Filters:</span>
            </div>
            <select
              value={tacticFilter}
              onChange={(e) => setTacticFilter(e.target.value)}
              className="px-3 py-1.5 bg-card border rounded-md text-sm"
            >
              <option value="">All Tactics</option>
              {MITRE_TACTICS.map((tactic) => (
                <option key={tactic} value={tactic}>{tactic}</option>
              ))}
            </select>
            <select
              value={platformFilter}
              onChange={(e) => setPlatformFilter(e.target.value)}
              className="px-3 py-1.5 bg-card border rounded-md text-sm"
            >
              <option value="">All Platforms</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
              <option value="macos">macOS</option>
              <option value="aws">AWS</option>
              <option value="azure">Azure</option>
              <option value="gcp">GCP</option>
            </select>
            <span className="text-sm text-muted-foreground">
              {filteredTemplates?.length || 0} templates
            </span>
          </div>

          {/* Template Grid */}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {isLoadingTemplates ? (
              <div className="col-span-full p-8 text-center text-muted-foreground bg-card rounded-lg border">
                Loading templates...
              </div>
            ) : filteredTemplates?.length === 0 ? (
              <div className="col-span-full p-8 text-center text-muted-foreground bg-card rounded-lg border">
                <Zap size={48} className="mx-auto mb-4 opacity-50" />
                <p>No templates found</p>
                <p className="text-sm mt-2">
                  {syncStatus?.atomic_red_team_count === 0 && syncStatus?.stratus_red_team_count === 0
                    ? 'Click "Sync" to fetch techniques from GitHub'
                    : 'Try adjusting your filters'}
                </p>
              </div>
            ) : (
              filteredTemplates?.map((template) => (
                <TemplateCard
                  key={template.id}
                  template={template}
                  onRun={() => handleRunSimulation(template)}
                  onShowCommands={() => handleShowCommands(template)}
                  isRunning={isRunning}
                  isLoadingCommands={isLoadingCommands}
                />
              ))
            )}
          </div>
        </>
      ) : (
        /* Run History */
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">Simulation Run History</h2>
            <button
              onClick={() => refetchRuns()}
              className="flex items-center gap-2 px-3 py-1.5 bg-accent hover:bg-accent/80 rounded-md text-sm"
            >
              <RefreshCw size={14} />
              Refresh
            </button>
          </div>

          {isLoadingRuns ? (
            <div className="p-8 text-center text-muted-foreground bg-card rounded-lg border">
              Loading run history...
            </div>
          ) : runs?.items?.length === 0 ? (
            <div className="p-8 text-center text-muted-foreground bg-card rounded-lg border">
              <Clock size={48} className="mx-auto mb-4 opacity-50" />
              <p>No simulation runs yet</p>
              <p className="text-sm mt-2">Run a simulation to see results here</p>
            </div>
          ) : (
            <div className="space-y-4">
              {runs?.items?.map((run) => (
                <RunCard
                  key={run.id}
                  run={run}
                  onVerify={() => handleVerifyDetection(run.id)}
                  onMarkExecuted={() => handleMarkExecuted(run.id)}
                />
              ))}
            </div>
          )}
        </div>
      )}

      {/* Commands Modal */}
      {showCommandModal && commands && (
        <CommandModal
          commands={commands}
          template={selectedTemplate}
          onClose={() => {
            setShowCommandModal(false)
            setCommands(null)
            setSelectedTemplate(null)
          }}
          onCopy={copyToClipboard}
        />
      )}
    </div>
  )
}

function TemplateCard({
  template,
  onRun,
  onShowCommands,
  isRunning,
  isLoadingCommands,
}: {
  template: SimulationTemplateResponse
  onRun: () => void
  onShowCommands: () => void
  isRunning: boolean
  isLoadingCommands: boolean
}) {
  const [expanded, setExpanded] = useState(false)
  const isCloud = template.framework === 'stratus'

  return (
    <div className="bg-card rounded-lg border overflow-hidden">
      <div className="p-4">
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <div className="flex items-center gap-2">
              {isCloud ? (
                <Cloud size={16} className="text-blue-500" />
              ) : (
                <Monitor size={16} className="text-green-500" />
              )}
              <span className="text-xs text-muted-foreground font-mono">
                {template.mitre_technique_id || template.technique_id}
              </span>
            </div>
            <h3 className="font-semibold mt-1 line-clamp-1">{template.name}</h3>
          </div>
          <div className="flex items-center gap-1">
            <button
              onClick={onShowCommands}
              disabled={isLoadingCommands}
              className="flex items-center gap-1 px-2 py-1.5 bg-accent hover:bg-accent/80 rounded-md text-sm"
              title="View Commands"
            >
              <Terminal size={14} />
            </button>
            <button
              onClick={onRun}
              disabled={isRunning || !template.is_enabled}
              className="flex items-center gap-1 px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm disabled:opacity-50"
            >
              <Play size={14} />
              Run
            </button>
          </div>
        </div>

        <p className="text-sm text-muted-foreground mt-2 line-clamp-2">
          {template.description || 'No description available'}
        </p>

        <div className="flex items-center gap-2 mt-3 flex-wrap">
          {template.mitre_tactic && (
            <span className="text-xs bg-accent px-2 py-0.5 rounded">
              {template.mitre_tactic}
            </span>
          )}
          {template.platforms.slice(0, 3).map((platform) => (
            <span key={platform} className="text-xs bg-muted px-2 py-0.5 rounded">
              {platform}
            </span>
          ))}
          {template.executor_type && (
            <span className="text-xs bg-blue-500/10 text-blue-500 px-2 py-0.5 rounded">
              {template.executor_type}
            </span>
          )}
        </div>

        <button
          onClick={() => setExpanded(!expanded)}
          className="text-xs text-muted-foreground hover:text-foreground mt-3 flex items-center gap-1"
        >
          {expanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
          {expanded ? 'Hide details' : 'Show details'}
        </button>
      </div>

      {expanded && (
        <div className="border-t bg-muted/30 p-4">
          <div className="space-y-2 text-sm">
            <div>
              <span className="text-muted-foreground">Framework:</span>{' '}
              <span className="capitalize">{template.framework === 'atomic' ? 'Atomic Red Team' : 'Stratus Red Team'}</span>
            </div>
            <div>
              <span className="text-muted-foreground">Platforms:</span>{' '}
              {template.platforms.join(', ')}
            </div>
            {template.executor_type && (
              <div>
                <span className="text-muted-foreground">Executor:</span>{' '}
                {template.executor_type}
              </div>
            )}
            {template.cloud_provider && (
              <div>
                <span className="text-muted-foreground">Cloud Provider:</span>{' '}
                {template.cloud_provider.toUpperCase()}
              </div>
            )}
            {template.cloud_permissions && template.cloud_permissions.length > 0 && (
              <div>
                <span className="text-muted-foreground">Required Permissions:</span>{' '}
                <span className="font-mono text-xs">{template.cloud_permissions.join(', ')}</span>
              </div>
            )}
            <div className="mt-2">
              <p className="text-muted-foreground mb-1">Description:</p>
              <p className="text-sm">{template.description || 'No description available'}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function RunCard({
  run,
  onVerify,
  onMarkExecuted,
}: {
  run: SimulationRunResponse
  onVerify: () => void
  onMarkExecuted: () => void
}) {
  const [expanded, setExpanded] = useState(false)
  const statusConfig = STATUS_COLORS[run.status] || STATUS_COLORS.pending
  const StatusIcon = statusConfig.icon

  const detectionStatus = run.detection_found
    ? 'detected'
    : run.status === 'completed'
      ? 'not_detected'
      : 'pending'
  const detectionConfig = STATUS_COLORS[detectionStatus]
  const DetectionIcon = detectionConfig.icon

  return (
    <div className="bg-card rounded-lg border overflow-hidden">
      <div className="p-4">
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <div className="flex items-center gap-3">
              <h3 className="font-semibold">Template {run.template_id.slice(0, 8)}...</h3>
              <span className={cn(
                'flex items-center gap-1 text-xs px-2 py-0.5 rounded',
                statusConfig.bg,
                statusConfig.text
              )}>
                <StatusIcon size={12} className={run.status === 'running' ? 'animate-spin' : ''} />
                {run.status}
              </span>
            </div>
            <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
              <span>Targets: {run.targets.join(', ')}</span>
              {run.started_at && <span>Started: {new Date(run.started_at).toLocaleString()}</span>}
              {run.completed_at && run.started_at && (
                <span>Duration: {Math.round((new Date(run.completed_at).getTime() - new Date(run.started_at).getTime()) / 1000)}s</span>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2">
            {/* Detection Status */}
            <div className={cn(
              'flex items-center gap-1 px-3 py-1.5 rounded-md text-sm',
              detectionConfig.bg,
              detectionConfig.text
            )}>
              <DetectionIcon size={14} />
              {run.detection_found ? 'Detected' : run.status === 'completed' ? 'Not Detected' : 'Pending'}
            </div>
            {run.status === 'running' && (
              <button
                onClick={onMarkExecuted}
                className="flex items-center gap-1 px-3 py-1.5 bg-green-500/10 text-green-500 hover:bg-green-500/20 rounded-md text-sm"
              >
                <Check size={14} />
                Mark Executed
              </button>
            )}
            {run.status === 'completed' && !run.detection_found && (
              <button
                onClick={onVerify}
                className="flex items-center gap-1 px-3 py-1.5 bg-accent hover:bg-accent/80 rounded-md text-sm"
              >
                <RefreshCw size={14} />
                Verify
              </button>
            )}
            <button
              onClick={() => setExpanded(!expanded)}
              className="p-2 bg-accent hover:bg-accent/80 rounded-md"
            >
              {expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
            </button>
          </div>
        </div>
      </div>

      {expanded && (
        <div className="border-t bg-muted/30 p-4 space-y-4">
          <div>
            <h4 className="font-medium mb-2">Simulation Details</h4>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-muted-foreground">Template ID:</span>{' '}
                <span className="font-mono text-xs">{run.template_id}</span>
              </div>
              <div>
                <span className="text-muted-foreground">Detection Expected:</span>{' '}
                {run.detection_expected ? 'Yes' : 'No'}
              </div>
              <div>
                <span className="text-muted-foreground">Triggered By:</span>{' '}
                {run.triggered_by}
              </div>
              {run.detection_rule_id && (
                <div>
                  <span className="text-muted-foreground">Detection Rule:</span>{' '}
                  <span className="font-mono text-xs">{run.detection_rule_id}</span>
                </div>
              )}
            </div>
          </div>

          {run.error_message && (
            <div className="bg-red-500/10 border border-red-500/20 rounded p-3">
              <div className="flex items-center gap-2 text-red-500 text-sm">
                <AlertCircle size={16} />
                <span className="font-medium">Error</span>
              </div>
              <p className="text-sm text-red-400 mt-1">{run.error_message}</p>
            </div>
          )}

          {run.results && run.results.length > 0 && (
            <div>
              <h4 className="font-medium mb-2">Results by Target</h4>
              <div className="space-y-2">
                {run.results.map((result, i) => (
                  <div key={i} className="flex items-center justify-between p-2 bg-background rounded text-sm">
                    <span className="font-mono">{result.target}</span>
                    <div className="flex items-center gap-4">
                      <span className={result.success ? 'text-green-500' : 'text-red-500'}>
                        {result.success ? 'Success' : 'Failed'}
                      </span>
                      {result.detected_at && (
                        <span className="text-muted-foreground">
                          Detected at: {new Date(result.detected_at).toLocaleString()}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function CommandModal({
  commands,
  template,
  onClose,
  onCopy,
}: {
  commands: ManualCommandsResponse
  template: SimulationTemplateResponse | null
  onClose: () => void
  onCopy: (text: string) => void
}) {
  const [copied, setCopied] = useState<string | null>(null)

  const handleCopy = (text: string, type: string) => {
    onCopy(text)
    setCopied(type)
    setTimeout(() => setCopied(null), 2000)
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-card rounded-lg border max-w-3xl w-full max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b">
          <div>
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <Terminal size={20} />
              Manual Execution Commands
            </h2>
            <p className="text-sm text-muted-foreground mt-1">
              {commands.name}
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-accent rounded-md"
          >
            <XCircle size={20} />
          </button>
        </div>

        <div className="p-4 space-y-4">
          {/* Instructions */}
          <div>
            <h3 className="font-medium mb-2">Instructions</h3>
            <ol className="space-y-1 text-sm">
              {commands.instructions.map((instruction, i) => (
                <li key={i} className="text-muted-foreground">{instruction}</li>
              ))}
            </ol>
          </div>

          {/* Execution Command */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-medium">Execution Command</h3>
              <button
                onClick={() => handleCopy(commands.execution_command, 'exec')}
                className="flex items-center gap-1 text-xs px-2 py-1 bg-accent hover:bg-accent/80 rounded"
              >
                {copied === 'exec' ? <Check size={12} /> : <Copy size={12} />}
                {copied === 'exec' ? 'Copied!' : 'Copy'}
              </button>
            </div>
            <pre className="bg-muted p-3 rounded text-sm overflow-x-auto font-mono">
              {commands.execution_command || 'No command available'}
            </pre>
          </div>

          {/* Cleanup Command */}
          {commands.cleanup_command && (
            <div>
              <div className="flex items-center justify-between mb-2">
                <h3 className="font-medium">Cleanup Command</h3>
                <button
                  onClick={() => handleCopy(commands.cleanup_command, 'cleanup')}
                  className="flex items-center gap-1 text-xs px-2 py-1 bg-accent hover:bg-accent/80 rounded"
                >
                  {copied === 'cleanup' ? <Check size={12} /> : <Copy size={12} />}
                  {copied === 'cleanup' ? 'Copied!' : 'Copy'}
                </button>
              </div>
              <pre className="bg-muted p-3 rounded text-sm overflow-x-auto font-mono">
                {commands.cleanup_command}
              </pre>
            </div>
          )}

          {/* Parameters */}
          {Object.keys(commands.input_arguments).length > 0 && (
            <div>
              <h3 className="font-medium mb-2">Input Arguments</h3>
              <div className="bg-muted rounded p-3">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-muted-foreground text-left">
                      <th className="pb-2">Parameter</th>
                      <th className="pb-2">Value</th>
                      <th className="pb-2">Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(commands.input_arguments).map(([key, info]) => (
                      <tr key={key} className="border-t border-border">
                        <td className="py-2 font-mono text-xs">{key}</td>
                        <td className="py-2 font-mono text-xs">
                          {String(commands.applied_parameters[key] || '')}
                        </td>
                        <td className="py-2 text-muted-foreground">
                          {typeof info === 'object' && info !== null ? (info as { description?: string }).description || '' : ''}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Dependencies */}
          {commands.dependencies && commands.dependencies.length > 0 && (
            <div>
              <h3 className="font-medium mb-2">Dependencies</h3>
              <ul className="list-disc list-inside text-sm text-muted-foreground space-y-1">
                {commands.dependencies.map((dep, i) => (
                  <li key={i}>{typeof dep === 'object' ? JSON.stringify(dep) : String(dep)}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Cloud Permissions */}
          {commands.cloud_permissions && commands.cloud_permissions.length > 0 && (
            <div>
              <h3 className="font-medium mb-2">Required Permissions</h3>
              <div className="flex flex-wrap gap-2">
                {commands.cloud_permissions.map((perm, i) => (
                  <span key={i} className="text-xs bg-blue-500/10 text-blue-500 px-2 py-1 rounded font-mono">
                    {perm}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="p-4 border-t bg-muted/30 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm bg-accent hover:bg-accent/80 rounded-md"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
