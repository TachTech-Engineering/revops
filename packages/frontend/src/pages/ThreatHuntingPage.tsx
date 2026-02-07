import { useState } from 'react'
import {
  Crosshair,
  Sparkles,
  Search,
  Play,
  RefreshCw,
  BookOpen,
  Clock,
  Target,
  AlertTriangle,
  CheckCircle,
  ChevronRight,
  History,
  Lightbulb,
  FileText,
  Download,
  Plus,
} from 'lucide-react'
import { cn } from '../lib/utils'

interface HuntingHypothesis {
  id: string
  title: string
  description: string
  mitre_techniques: string[]
  suggested_queries: Array<{
    name: string
    sql: string
    description: string
  }>
  data_sources: string[]
  confidence: number
}

interface HuntResult {
  id: string
  hypothesis_id: string
  query_name: string
  status: 'running' | 'completed' | 'failed'
  results_count: number
  findings: Array<{
    severity: 'critical' | 'high' | 'medium' | 'low'
    description: string
    evidence: string
  }>
  executed_at: string
}

// Mock data
const mockHypotheses: HuntingHypothesis[] = [
  {
    id: '1',
    title: 'Potential Credential Dumping Activity',
    description: 'Hunt for signs of credential dumping tools like Mimikatz or LSASS memory access attempts',
    mitre_techniques: ['T1003', 'T1003.001', 'T1003.002'],
    suggested_queries: [
      {
        name: 'LSASS Access Detection',
        sql: `SELECT * FROM windows_security_events
WHERE event_id IN (4656, 4663)
AND object_name LIKE '%lsass%'
AND p_event_time > NOW() - INTERVAL 7 DAY`,
        description: 'Detect attempts to access LSASS process memory',
      },
      {
        name: 'Suspicious PowerShell Commands',
        sql: `SELECT * FROM windows_security_events
WHERE event_id = 4104
AND script_block LIKE '%Invoke-Mimikatz%'
AND p_event_time > NOW() - INTERVAL 7 DAY`,
        description: 'Hunt for Mimikatz-related PowerShell activity',
      },
    ],
    data_sources: ['Windows Security Events', 'Sysmon', 'EDR'],
    confidence: 0.85,
  },
  {
    id: '2',
    title: 'Lateral Movement via RDP',
    description: 'Identify potential lateral movement using Remote Desktop Protocol across the network',
    mitre_techniques: ['T1021.001'],
    suggested_queries: [
      {
        name: 'Unusual RDP Connections',
        sql: `SELECT src_ip, dst_ip, user_name, COUNT(*) as connection_count
FROM network_logs
WHERE dst_port = 3389
AND p_event_time > NOW() - INTERVAL 24 HOUR
GROUP BY src_ip, dst_ip, user_name
HAVING connection_count > 5`,
        description: 'Find hosts making multiple RDP connections',
      },
    ],
    data_sources: ['Network Logs', 'Windows Events'],
    confidence: 0.78,
  },
  {
    id: '3',
    title: 'Data Exfiltration via Cloud Storage',
    description: 'Detect potential data exfiltration to unauthorized cloud storage services',
    mitre_techniques: ['T1567', 'T1567.002'],
    suggested_queries: [
      {
        name: 'Unusual Cloud Upload Activity',
        sql: `SELECT user_email, service_name, SUM(bytes_transferred) as total_bytes
FROM cloud_activity_logs
WHERE action = 'upload'
AND p_event_time > NOW() - INTERVAL 24 HOUR
GROUP BY user_email, service_name
HAVING total_bytes > 100000000`,
        description: 'Identify large uploads to cloud services',
      },
    ],
    data_sources: ['Cloud Audit Logs', 'DLP'],
    confidence: 0.72,
  },
]

const mockHuntHistory: HuntResult[] = [
  {
    id: '1',
    hypothesis_id: '1',
    query_name: 'LSASS Access Detection',
    status: 'completed',
    results_count: 3,
    findings: [
      {
        severity: 'high',
        description: 'Suspicious LSASS access from unknown process',
        evidence: 'Process: unknown.exe, Time: 2024-01-15 14:32:00',
      },
    ],
    executed_at: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
  },
  {
    id: '2',
    hypothesis_id: '2',
    query_name: 'Unusual RDP Connections',
    status: 'completed',
    results_count: 0,
    findings: [],
    executed_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
  },
]

export default function ThreatHuntingPage() {
  const [selectedHypothesis, setSelectedHypothesis] = useState<HuntingHypothesis | null>(null)
  const [customQuery, setCustomQuery] = useState('')
  const [naturalLanguageQuery, setNaturalLanguageQuery] = useState('')
  const [isGenerating, setIsGenerating] = useState(false)
  const [isRunning, setIsRunning] = useState(false)
  const [activeTab, setActiveTab] = useState<'hypotheses' | 'custom' | 'history'>('hypotheses')
  const [huntResults, setHuntResults] = useState<HuntResult[]>(mockHuntHistory)

  const handleGenerateHypothesis = async () => {
    if (!naturalLanguageQuery.trim()) return
    setIsGenerating(true)
    // Simulate AI generation
    await new Promise((resolve) => setTimeout(resolve, 2000))
    setIsGenerating(false)
    // Would add generated hypothesis to list
  }

  const handleRunQuery = async (query: string) => {
    setIsRunning(true)
    // Simulate query execution
    await new Promise((resolve) => setTimeout(resolve, 3000))
    setIsRunning(false)
    // Would add results to huntResults
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Crosshair className="text-primary" />
            Threat Hunting Assistant
          </h1>
          <p className="text-muted-foreground mt-1">
            AI-powered threat hunting with hypothesis generation and guided investigations
          </p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90">
          <Plus size={16} />
          New Hunt
        </button>
      </div>

      {/* AI Query Input */}
      <div className="bg-card rounded-lg border p-4">
        <div className="flex items-center gap-3 mb-3">
          <Sparkles className="text-primary" size={20} />
          <h3 className="font-medium">Ask AI to Generate a Hunt</h3>
        </div>
        <div className="flex gap-2">
          <input
            type="text"
            value={naturalLanguageQuery}
            onChange={(e) => setNaturalLanguageQuery(e.target.value)}
            placeholder="Describe what you want to hunt for... (e.g., 'Find signs of PowerShell-based attacks in the last week')"
            className="flex-1 px-4 py-2 bg-background border rounded-md"
          />
          <button
            onClick={handleGenerateHypothesis}
            disabled={isGenerating || !naturalLanguageQuery.trim()}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
          >
            {isGenerating ? (
              <>
                <RefreshCw size={16} className="animate-spin" />
                Generating...
              </>
            ) : (
              <>
                <Sparkles size={16} />
                Generate Hunt
              </>
            )}
          </button>
        </div>
        <div className="flex items-center gap-4 mt-3 text-xs text-muted-foreground">
          <span className="flex items-center gap-1">
            <Lightbulb size={12} />
            Try: "Hunt for signs of data exfiltration"
          </span>
          <span className="flex items-center gap-1">
            <Lightbulb size={12} />
            Try: "Look for persistence mechanisms"
          </span>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b">
        <button
          onClick={() => setActiveTab('hypotheses')}
          className={cn(
            'px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors',
            activeTab === 'hypotheses'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          )}
        >
          <Target size={14} className="inline mr-2" />
          Hunting Hypotheses
        </button>
        <button
          onClick={() => setActiveTab('custom')}
          className={cn(
            'px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors',
            activeTab === 'custom'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          )}
        >
          <Search size={14} className="inline mr-2" />
          Custom Query
        </button>
        <button
          onClick={() => setActiveTab('history')}
          className={cn(
            'px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors',
            activeTab === 'history'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          )}
        >
          <History size={14} className="inline mr-2" />
          Hunt History
        </button>
      </div>

      {/* Hypotheses Tab */}
      {activeTab === 'hypotheses' && (
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Hypothesis List */}
          <div className="space-y-4">
            <h3 className="font-medium">Suggested Hypotheses</h3>
            {mockHypotheses.map((hypothesis) => (
              <button
                key={hypothesis.id}
                onClick={() => setSelectedHypothesis(hypothesis)}
                className={cn(
                  'w-full text-left p-4 rounded-lg border transition-colors',
                  selectedHypothesis?.id === hypothesis.id
                    ? 'border-primary bg-primary/5'
                    : 'hover:bg-muted/50'
                )}
              >
                <div className="flex items-start justify-between mb-2">
                  <h4 className="font-medium">{hypothesis.title}</h4>
                  <span className="text-xs bg-primary/20 text-primary px-2 py-0.5 rounded">
                    {(hypothesis.confidence * 100).toFixed(0)}% match
                  </span>
                </div>
                <p className="text-sm text-muted-foreground mb-3">{hypothesis.description}</p>
                <div className="flex items-center gap-4 text-xs text-muted-foreground">
                  <span className="flex items-center gap-1">
                    <Target size={10} />
                    {hypothesis.mitre_techniques.length} techniques
                  </span>
                  <span className="flex items-center gap-1">
                    <FileText size={10} />
                    {hypothesis.suggested_queries.length} queries
                  </span>
                </div>
              </button>
            ))}
          </div>

          {/* Hypothesis Detail */}
          {selectedHypothesis ? (
            <div className="bg-card rounded-lg border p-4 space-y-4">
              <div>
                <h3 className="font-semibold text-lg">{selectedHypothesis.title}</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  {selectedHypothesis.description}
                </p>
              </div>

              {/* MITRE Techniques */}
              <div>
                <h4 className="text-sm font-medium mb-2">MITRE ATT&CK Techniques</h4>
                <div className="flex flex-wrap gap-2">
                  {selectedHypothesis.mitre_techniques.map((tech) => (
                    <span
                      key={tech}
                      className="px-2 py-1 bg-red-500/20 text-red-400 rounded text-xs"
                    >
                      {tech}
                    </span>
                  ))}
                </div>
              </div>

              {/* Data Sources */}
              <div>
                <h4 className="text-sm font-medium mb-2">Required Data Sources</h4>
                <div className="flex flex-wrap gap-2">
                  {selectedHypothesis.data_sources.map((source) => (
                    <span
                      key={source}
                      className="px-2 py-1 bg-muted rounded text-xs"
                    >
                      {source}
                    </span>
                  ))}
                </div>
              </div>

              {/* Suggested Queries */}
              <div>
                <h4 className="text-sm font-medium mb-2">Suggested Queries</h4>
                <div className="space-y-3">
                  {selectedHypothesis.suggested_queries.map((query, index) => (
                    <div key={index} className="bg-muted/50 rounded-lg p-3">
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-medium text-sm">{query.name}</span>
                        <button
                          onClick={() => handleRunQuery(query.sql)}
                          disabled={isRunning}
                          className="flex items-center gap-1 px-3 py-1 bg-primary text-primary-foreground rounded text-xs hover:bg-primary/90 disabled:opacity-50"
                        >
                          {isRunning ? (
                            <RefreshCw size={12} className="animate-spin" />
                          ) : (
                            <Play size={12} />
                          )}
                          Run
                        </button>
                      </div>
                      <p className="text-xs text-muted-foreground mb-2">{query.description}</p>
                      <pre className="text-xs bg-background p-2 rounded overflow-x-auto">
                        {query.sql}
                      </pre>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-muted/30 rounded-lg border border-dashed p-8 flex flex-col items-center justify-center text-center">
              <Crosshair className="text-muted-foreground mb-4" size={48} />
              <p className="text-muted-foreground">Select a hypothesis to view details and run queries</p>
            </div>
          )}
        </div>
      )}

      {/* Custom Query Tab */}
      {activeTab === 'custom' && (
        <div className="bg-card rounded-lg border p-4 space-y-4">
          <h3 className="font-medium">Custom Hunt Query</h3>
          <textarea
            value={customQuery}
            onChange={(e) => setCustomQuery(e.target.value)}
            placeholder="Enter your SQL query here..."
            className="w-full h-48 px-4 py-3 bg-background border rounded-md font-mono text-sm"
          />
          <div className="flex justify-end gap-2">
            <button className="px-4 py-2 border rounded-md hover:bg-accent">
              <BookOpen size={14} className="inline mr-2" />
              Query Library
            </button>
            <button
              onClick={() => handleRunQuery(customQuery)}
              disabled={isRunning || !customQuery.trim()}
              className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
            >
              {isRunning ? <RefreshCw size={16} className="animate-spin" /> : <Play size={16} />}
              Execute Query
            </button>
          </div>
        </div>
      )}

      {/* History Tab */}
      {activeTab === 'history' && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="font-medium">Recent Hunts</h3>
            <button className="flex items-center gap-2 px-3 py-1.5 border rounded-md text-sm hover:bg-accent">
              <Download size={14} />
              Export Results
            </button>
          </div>
          <div className="space-y-3">
            {huntResults.map((result) => (
              <div key={result.id} className="bg-card rounded-lg border p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-3">
                    {result.status === 'completed' ? (
                      <CheckCircle className="text-green-400" size={18} />
                    ) : result.status === 'running' ? (
                      <RefreshCw className="text-blue-400 animate-spin" size={18} />
                    ) : (
                      <AlertTriangle className="text-red-400" size={18} />
                    )}
                    <span className="font-medium">{result.query_name}</span>
                  </div>
                  <span className="text-xs text-muted-foreground flex items-center gap-1">
                    <Clock size={10} />
                    {new Date(result.executed_at).toLocaleString()}
                  </span>
                </div>
                <div className="flex items-center gap-4 text-sm">
                  <span className="text-muted-foreground">
                    {result.results_count} results found
                  </span>
                  {result.findings.length > 0 && (
                    <span className="text-yellow-400 flex items-center gap-1">
                      <AlertTriangle size={12} />
                      {result.findings.length} findings
                    </span>
                  )}
                </div>
                {result.findings.length > 0 && (
                  <div className="mt-3 pt-3 border-t space-y-2">
                    {result.findings.map((finding, index) => (
                      <div
                        key={index}
                        className={cn(
                          'p-2 rounded text-sm',
                          finding.severity === 'critical' || finding.severity === 'high'
                            ? 'bg-red-500/10 border border-red-500/30'
                            : 'bg-yellow-500/10 border border-yellow-500/30'
                        )}
                      >
                        <p className="font-medium">{finding.description}</p>
                        <p className="text-xs text-muted-foreground mt-1">{finding.evidence}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
