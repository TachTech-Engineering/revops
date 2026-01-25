import { useState, useRef } from 'react'
import { ArrowRightLeft, Copy, Check, AlertTriangle, Upload, FileText, Download, Trash2, Info, ChevronDown, ChevronRight, Code2, Database } from 'lucide-react'
import Editor from '@monaco-editor/react'
import { useConvertSPLMutation } from '../api/pantherApi'
import { getSeverityColor, cn } from '../lib/utils'

interface BulkRule {
  id: string
  name: string
  spl: string
  severity: string
  status: 'pending' | 'converting' | 'success' | 'error'
  result?: {
    sourceCode: string
    className: string
    todos: string[]
  }
  error?: string
}

interface ParseDetails {
  index?: string
  sourcetype?: string
  evalFields?: number
  statsCommands?: number
  whereConditions?: number
}

type InputMode = 'single' | 'bulk'
type FileFormat = 'csv' | 'json' | 'conf' | 'text'

export default function ConverterPage() {
  const [mode, setMode] = useState<InputMode>('single')

  // Single mode state
  const [splQuery, setSplQuery] = useState('')
  const [ruleId, setRuleId] = useState('Custom.ConvertedRule')
  const [severity, setSeverity] = useState('MEDIUM')
  const [copied, setCopied] = useState(false)
  const [showTodos, setShowTodos] = useState(true)
  const [showTestCode, setShowTestCode] = useState(false)

  // Bulk mode state
  const [bulkRules, setBulkRules] = useState<BulkRule[]>([])
  const [defaultSeverity, setDefaultSeverity] = useState('MEDIUM')
  const [rulePrefix, setRulePrefix] = useState('Custom.')
  const fileInputRef = useRef<HTMLInputElement>(null)

  const [convertSPL, { data: result, isLoading, error }] = useConvertSPLMutation()

  const handleConvert = async () => {
    if (!splQuery.trim()) return
    try {
      await convertSPL({
        spl: splQuery,
        ruleId,
        severity,
      }).unwrap()
    } catch (err) {
      console.error('Conversion failed:', err)
    }
  }

  const handleCopy = async (code?: string) => {
    const textToCopy = code || result?.sourceCode
    if (!textToCopy) return
    await navigator.clipboard.writeText(textToCopy)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const parseFile = (content: string, format: FileFormat): BulkRule[] => {
    const rules: BulkRule[] = []

    switch (format) {
      case 'csv': {
        // Expect CSV with columns: name, spl, severity (optional)
        const lines = content.split('\n').filter(l => l.trim())
        const hasHeader = lines[0]?.toLowerCase().includes('name') || lines[0]?.toLowerCase().includes('spl')
        const dataLines = hasHeader ? lines.slice(1) : lines

        dataLines.forEach((line, i) => {
          // Simple CSV parsing (handles quoted fields)
          const matches = line.match(/("([^"]*)"|[^,]+)/g)
          if (matches && matches.length >= 2) {
            const name = matches[0]?.replace(/^"|"$/g, '').trim() || `Rule${i + 1}`
            const spl = matches[1]?.replace(/^"|"$/g, '').trim()
            const sev = matches[2]?.replace(/^"|"$/g, '').trim().toUpperCase() || defaultSeverity

            if (spl) {
              rules.push({
                id: `${rulePrefix}${name.replace(/[^a-zA-Z0-9]/g, '')}`,
                name,
                spl,
                severity: ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(sev) ? sev : defaultSeverity,
                status: 'pending'
              })
            }
          }
        })
        break
      }

      case 'json': {
        try {
          const data = JSON.parse(content)
          const items = Array.isArray(data) ? data : data.searches || data.rules || data.queries || [data]

          items.forEach((item: Record<string, unknown>, i: number) => {
            const name = (item.name || item.title || item.search_name || `Rule${i + 1}`) as string
            const spl = (item.spl || item.query || item.search || item.searchQuery) as string
            const sev = ((item.severity || item.priority || defaultSeverity) as string).toUpperCase()

            if (spl) {
              rules.push({
                id: `${rulePrefix}${name.replace(/[^a-zA-Z0-9]/g, '')}`,
                name,
                spl,
                severity: ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(sev) ? sev : defaultSeverity,
                status: 'pending'
              })
            }
          })
        } catch {
          console.error('Failed to parse JSON')
        }
        break
      }

      case 'conf': {
        // Parse Splunk savedsearches.conf format
        const stanzaRegex = /\[([^\]]+)\]/g
        const searchRegex = /search\s*=\s*(.+?)(?=\n[a-zA-Z]|\n\[|$)/gs

        let match
        const stanzas: string[] = []
        while ((match = stanzaRegex.exec(content)) !== null) {
          stanzas.push(match[1])
        }

        const sections = content.split(/\[([^\]]+)\]/).filter(s => s.trim())

        for (let i = 0; i < sections.length; i += 2) {
          const name = sections[i]?.trim()
          const body = sections[i + 1] || ''

          const searchMatch = body.match(/search\s*=\s*(.+?)(?=\n[a-zA-Z_]|$)/s)
          if (name && searchMatch) {
            const spl = searchMatch[1].trim().replace(/\\\n/g, ' ')

            // Try to extract severity from alert.severity
            const sevMatch = body.match(/alert\.severity\s*=\s*(\d+)/)
            let sev = defaultSeverity
            if (sevMatch) {
              const sevNum = parseInt(sevMatch[1])
              sev = sevNum >= 5 ? 'CRITICAL' : sevNum >= 4 ? 'HIGH' : sevNum >= 3 ? 'MEDIUM' : sevNum >= 2 ? 'LOW' : 'INFO'
            }

            rules.push({
              id: `${rulePrefix}${name.replace(/[^a-zA-Z0-9]/g, '')}`,
              name,
              spl,
              severity: sev,
              status: 'pending'
            })
          }
        }
        break
      }

      case 'text': {
        // Plain text - one SPL query per line or separated by blank lines
        const queries = content.split(/\n\s*\n/).filter(q => q.trim())

        queries.forEach((spl, i) => {
          rules.push({
            id: `${rulePrefix}Rule${i + 1}`,
            name: `Rule ${i + 1}`,
            spl: spl.trim(),
            severity: defaultSeverity,
            status: 'pending'
          })
        })
        break
      }
    }

    return rules
  }

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    const reader = new FileReader()
    reader.onload = (event) => {
      const content = event.target?.result as string

      // Detect format
      let format: FileFormat = 'text'
      if (file.name.endsWith('.csv')) format = 'csv'
      else if (file.name.endsWith('.json')) format = 'json'
      else if (file.name.endsWith('.conf')) format = 'conf'
      else if (content.trim().startsWith('[') || content.trim().startsWith('{')) format = 'json'
      else if (content.includes('[') && content.includes('search =')) format = 'conf'

      const rules = parseFile(content, format)
      setBulkRules(rules)
    }
    reader.readAsText(file)

    // Reset input
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  const handleBulkConvert = async () => {
    for (let i = 0; i < bulkRules.length; i++) {
      const rule = bulkRules[i]
      if (rule.status === 'success') continue

      setBulkRules(prev => prev.map((r, idx) =>
        idx === i ? { ...r, status: 'converting' } : r
      ))

      try {
        const res = await convertSPL({
          spl: rule.spl,
          ruleId: rule.id,
          severity: rule.severity,
        }).unwrap()

        setBulkRules(prev => prev.map((r, idx) =>
          idx === i ? {
            ...r,
            status: 'success',
            result: {
              sourceCode: res.sourceCode,
              className: res.className,
              todos: res.todos
            }
          } : r
        ))
      } catch (err) {
        setBulkRules(prev => prev.map((r, idx) =>
          idx === i ? { ...r, status: 'error', error: 'Conversion failed' } : r
        ))
      }
    }
  }

  const handleDownloadAll = () => {
    const successfulRules = bulkRules.filter(r => r.status === 'success' && r.result)

    if (successfulRules.length === 0) return

    // Create a zip-like download (single file with all rules separated)
    const content = successfulRules.map(r =>
      `# ${r.name} (${r.id})\n# Original SPL: ${r.spl.substring(0, 100)}...\n\n${r.result!.sourceCode}`
    ).join('\n\n' + '='.repeat(80) + '\n\n')

    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'panther_rules.py'
    a.click()
    URL.revokeObjectURL(url)
  }

  const removeRule = (index: number) => {
    setBulkRules(prev => prev.filter((_, i) => i !== index))
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Splunk SPL to Panther Converter</h1>
        <p className="text-muted-foreground">Convert Splunk Search Processing Language (SPL) queries to Panther detection rules</p>
      </div>

      {/* Mode Toggle */}
      <div className="flex gap-2">
        <button
          onClick={() => setMode('single')}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
            mode === 'single'
              ? 'bg-primary text-primary-foreground'
              : 'bg-muted hover:bg-muted/80'
          }`}
        >
          Single Query
        </button>
        <button
          onClick={() => setMode('bulk')}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
            mode === 'bulk'
              ? 'bg-primary text-primary-foreground'
              : 'bg-muted hover:bg-muted/80'
          }`}
        >
          Bulk Upload
        </button>
      </div>

      {mode === 'single' ? (
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Single Input */}
          <div className="space-y-4">
            <div className="rounded-lg border bg-background p-6 space-y-4">
              <h2 className="font-semibold">SPL Query</h2>

              <div>
                <label className="block text-sm font-medium mb-1">Rule ID</label>
                <input
                  type="text"
                  value={ruleId}
                  onChange={(e) => setRuleId(e.target.value)}
                  placeholder="Custom.MyRule"
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">Severity</label>
                <select
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value)}
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                >
                  <option value="INFO">Info</option>
                  <option value="LOW">Low</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="HIGH">High</option>
                  <option value="CRITICAL">Critical</option>
                </select>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="block text-sm font-medium">SPL Query</label>
                  <div className="relative group">
                    <button className="text-xs text-muted-foreground hover:text-foreground transition-colors">
                      Example queries ▾
                    </button>
                    <div className="absolute right-0 top-full mt-1 w-80 bg-card border border-border rounded-lg shadow-lg z-10 hidden group-hover:block">
                      <div className="p-2 space-y-1 text-xs">
                        <button
                          onClick={() => setSplQuery(`sourcetype=okta eventType="user.session.start" outcome.result=FAILURE
| stats count by actor.alternateId
| where count > 5`)}
                          className="block w-full text-left p-2 hover:bg-accent rounded transition-colors"
                        >
                          <span className="font-medium text-foreground">Failed Logins (Okta)</span>
                          <span className="block text-muted-foreground">Threshold-based detection</span>
                        </button>
                        <button
                          onClick={() => setSplQuery(`index=edr earliest=-1h
| eval host=coalesce(hostname, ComputerName, HostName)
| eval is_download = if(match(lower(process_name),"powershell") AND match(lower(command_line),"downloadstring|downloadfile|wget|curl"), 1, 0)
| stats max(is_download) as download_detected by host
| where download_detected=1`)}
                          className="block w-full text-left p-2 hover:bg-accent rounded transition-colors"
                        >
                          <span className="font-medium text-foreground">PowerShell Download (EDR)</span>
                          <span className="block text-muted-foreground">Complex eval with coalesce/match</span>
                        </button>
                        <button
                          onClick={() => setSplQuery(`index=crowdstrike earliest=-24h
| eval severity_score=if(Severity="Critical", 4, if(Severity="High", 3, if(Severity="Medium", 2, 1)))
| stats count as alert_count, sum(severity_score) as total_score by ComputerName
| where alert_count > 10 OR total_score > 20`)}
                          className="block w-full text-left p-2 hover:bg-accent rounded transition-colors"
                        >
                          <span className="font-medium text-foreground">Alert Scoring (CrowdStrike)</span>
                          <span className="block text-muted-foreground">Nested if statements</span>
                        </button>
                        <button
                          onClick={() => setSplQuery(`index=aws_cloudtrail eventName=ConsoleLogin
| stats dc(sourceIPAddress) as unique_ips, values(sourceIPAddress) as ip_list by userIdentity.arn
| where unique_ips > 3`)}
                          className="block w-full text-left p-2 hover:bg-accent rounded transition-colors"
                        >
                          <span className="font-medium text-foreground">Multi-IP Login (AWS)</span>
                          <span className="block text-muted-foreground">Distinct count aggregation</span>
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
                <textarea
                  value={splQuery}
                  onChange={(e) => setSplQuery(e.target.value)}
                  placeholder={`sourcetype=okta eventType="user.session.start" outcome.result=FAILURE
| stats count by actor.alternateId
| where count > 5`}
                  className="w-full h-40 rounded-md border bg-background px-3 py-2 text-sm font-mono resize-none"
                />
              </div>

              <button
                onClick={handleConvert}
                disabled={isLoading || !splQuery.trim()}
                className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
              >
                <ArrowRightLeft size={16} />
                {isLoading ? 'Converting...' : 'Convert to Panther Rule'}
              </button>
            </div>
          </div>

          {/* Single Output */}
          <div className="space-y-4">
            {error && (
              <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4">
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle size={16} className="text-red-400" />
                  <p className="font-medium text-red-400">Conversion Error</p>
                </div>
                <p className="text-sm text-red-400/80 mb-3">
                  {(error as { data?: { detail?: string } })?.data?.detail || 'Failed to convert SPL query.'}
                </p>
                <div className="text-xs text-red-400/60 space-y-1">
                  <p className="font-medium">Common issues:</p>
                  <ul className="list-disc list-inside space-y-0.5 ml-2">
                    <li>Check for balanced parentheses and quotes</li>
                    <li>Ensure pipe characters are properly formatted</li>
                    <li>Complex subsearches may need manual conversion</li>
                    <li>Some advanced SPL functions require manual translation</li>
                  </ul>
                </div>
              </div>
            )}

            {result && (
              <>
                {/* Rule Summary Card */}
                <div className="rounded-lg border bg-card p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Code2 size={18} className="text-primary" />
                      <h3 className="font-semibold text-foreground">{result.className}</h3>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(result.severity)}`}>
                        {result.severity}
                      </span>
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${result.recommendedType === 'STREAMING' ? 'bg-green-500/20 text-green-400 border border-green-500/30' : 'bg-purple-500/20 text-purple-400 border border-purple-500/30'}`}>
                        {result.recommendedType}
                      </span>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3 text-sm">
                    <div className="flex items-center gap-2 text-muted-foreground">
                      <Database size={14} />
                      <span>Log Types:</span>
                      <span className="text-foreground font-mono text-xs">{result.logTypes.join(', ')}</span>
                    </div>
                    {result.isThresholdRule && (
                      <div className="text-muted-foreground">
                        Threshold Rule: <span className="text-foreground">{result.threshold || 'Configured in query'}</span>
                      </div>
                    )}
                  </div>

                  {result.recommendationReasons && result.recommendationReasons.length > 0 && (
                    <div className="text-xs text-muted-foreground bg-muted/50 rounded p-2">
                      <Info size={12} className="inline mr-1" />
                      {result.recommendationReasons.join(' • ')}
                    </div>
                  )}
                </div>

                {/* TODOs Section */}
                {result.todos.length > 0 && (
                  <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10">
                    <button
                      onClick={() => setShowTodos(!showTodos)}
                      className="flex items-center justify-between w-full px-4 py-3 text-left"
                    >
                      <div className="flex items-center gap-2">
                        <AlertTriangle size={16} className="text-yellow-400" />
                        <span className="font-medium text-yellow-400">
                          {result.todos.length} Item{result.todos.length !== 1 ? 's' : ''} Need Review
                        </span>
                      </div>
                      {showTodos ? <ChevronDown size={16} className="text-yellow-400" /> : <ChevronRight size={16} className="text-yellow-400" />}
                    </button>
                    {showTodos && (
                      <div className="px-4 pb-4 space-y-2">
                        {result.todos.map((todo, i) => (
                          <div key={i} className="flex items-start gap-2 text-sm text-yellow-400/90 bg-yellow-500/5 rounded p-2">
                            <span className="font-mono text-xs bg-yellow-500/20 px-1.5 py-0.5 rounded">{i + 1}</span>
                            <span>{todo}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Generated Code */}
                <div className="rounded-lg border bg-card overflow-hidden">
                  <div className="flex items-center justify-between border-b border-border px-4 py-2 bg-muted/50">
                    <h3 className="font-semibold text-sm text-foreground">Generated Python Code</h3>
                    <button
                      onClick={() => handleCopy()}
                      className="flex items-center gap-1 px-2 py-1 text-sm hover:bg-accent rounded transition-colors"
                    >
                      {copied ? <Check size={14} className="text-green-400" /> : <Copy size={14} />}
                      {copied ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                  <Editor
                    height="400px"
                    defaultLanguage="python"
                    value={result.sourceCode}
                    theme="vs-dark"
                    options={{
                      readOnly: true,
                      minimap: { enabled: false },
                      fontSize: 13,
                      lineNumbers: 'on',
                      scrollBeyondLastLine: false,
                      automaticLayout: true,
                    }}
                  />
                </div>

                {/* Test Code Section */}
                {result.testCode && (
                  <div className="rounded-lg border bg-card overflow-hidden">
                    <button
                      onClick={() => setShowTestCode(!showTestCode)}
                      className="flex items-center justify-between w-full border-b border-border px-4 py-2 bg-muted/50 text-left"
                    >
                      <h3 className="font-semibold text-sm text-foreground">Test Code Template</h3>
                      {showTestCode ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                    </button>
                    {showTestCode && (
                      <Editor
                        height="250px"
                        defaultLanguage="python"
                        value={result.testCode}
                        theme="vs-dark"
                        options={{
                          readOnly: true,
                          minimap: { enabled: false },
                          fontSize: 12,
                          lineNumbers: 'on',
                          scrollBeyondLastLine: false,
                          automaticLayout: true,
                        }}
                      />
                    )}
                  </div>
                )}
              </>
            )}

            {!result && !error && (
              <div className="rounded-lg border bg-background p-6 text-center text-muted-foreground">
                <ArrowRightLeft size={48} className="mx-auto mb-4 opacity-20" />
                <p>Enter an SPL query and click Convert to generate a Panther detection rule</p>
              </div>
            )}
          </div>
        </div>
      ) : (
        /* Bulk Mode */
        <div className="space-y-6">
          {/* Upload Section */}
          <div className="rounded-lg border bg-background p-6 space-y-4">
            <h2 className="font-semibold">Bulk Upload</h2>
            <p className="text-sm text-muted-foreground">
              Upload a file containing multiple SPL queries. Supported formats:
            </p>
            <ul className="text-sm text-muted-foreground list-disc list-inside">
              <li><strong>CSV</strong> - Columns: name, spl, severity (optional)</li>
              <li><strong>JSON</strong> - Array of objects with name/spl/severity fields</li>
              <li><strong>savedsearches.conf</strong> - Splunk native format</li>
              <li><strong>Text</strong> - One query per paragraph (separated by blank lines)</li>
            </ul>

            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <label className="block text-sm font-medium mb-1">Rule ID Prefix</label>
                <input
                  type="text"
                  value={rulePrefix}
                  onChange={(e) => setRulePrefix(e.target.value)}
                  placeholder="Custom."
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Default Severity</label>
                <select
                  value={defaultSeverity}
                  onChange={(e) => setDefaultSeverity(e.target.value)}
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                >
                  <option value="INFO">Info</option>
                  <option value="LOW">Low</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="HIGH">High</option>
                  <option value="CRITICAL">Critical</option>
                </select>
              </div>
            </div>

            <div className="flex gap-4">
              <input
                ref={fileInputRef}
                type="file"
                accept=".csv,.json,.conf,.txt"
                onChange={handleFileUpload}
                className="hidden"
              />
              <button
                onClick={() => fileInputRef.current?.click()}
                className="flex items-center gap-2 px-4 py-2 bg-muted hover:bg-muted/80 rounded-md text-sm font-medium"
              >
                <Upload size={16} />
                Upload File
              </button>

              {bulkRules.length > 0 && (
                <>
                  <button
                    onClick={handleBulkConvert}
                    disabled={isLoading}
                    className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
                  >
                    <ArrowRightLeft size={16} />
                    Convert All ({bulkRules.filter(r => r.status === 'pending').length} pending)
                  </button>

                  {bulkRules.some(r => r.status === 'success') && (
                    <button
                      onClick={handleDownloadAll}
                      className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-md text-sm font-medium"
                    >
                      <Download size={16} />
                      Download All ({bulkRules.filter(r => r.status === 'success').length})
                    </button>
                  )}
                </>
              )}
            </div>
          </div>

          {/* Rules List */}
          {bulkRules.length > 0 && (
            <div className="rounded-lg border bg-background">
              <div className="border-b px-4 py-3">
                <h3 className="font-semibold">{bulkRules.length} Rules to Convert</h3>
              </div>
              <div className="divide-y max-h-[600px] overflow-auto">
                {bulkRules.map((rule, index) => (
                  <div key={index} className="p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <FileText size={16} className="text-muted-foreground" />
                        <div>
                          <p className="font-medium">{rule.name}</p>
                          <p className="text-sm text-muted-foreground">{rule.id}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(rule.severity)}`}>
                          {rule.severity}
                        </span>
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                          rule.status === 'pending' ? 'bg-gray-500/20 text-gray-400' :
                          rule.status === 'converting' ? 'bg-blue-500/20 text-blue-400' :
                          rule.status === 'success' ? 'bg-green-500/20 text-green-400' :
                          'bg-red-500/20 text-red-400'
                        }`}>
                          {rule.status}
                        </span>
                        <button
                          onClick={() => removeRule(index)}
                          className="p-1 hover:bg-red-500/10 rounded text-red-400"
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </div>

                    <pre className="text-xs bg-muted p-2 rounded overflow-x-auto">
                      {rule.spl.length > 200 ? rule.spl.substring(0, 200) + '...' : rule.spl}
                    </pre>

                    {rule.status === 'success' && rule.result && (
                      <div className="mt-2">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-sm font-medium text-green-400">Converted: {rule.result.className}</span>
                          <button
                            onClick={() => handleCopy(rule.result!.sourceCode)}
                            className="flex items-center gap-1 px-2 py-1 text-xs hover:bg-accent rounded"
                          >
                            <Copy size={12} />
                            Copy
                          </button>
                        </div>
                        {rule.result.todos.length > 0 && (
                          <div className="flex items-center gap-1 text-xs text-yellow-400">
                            <AlertTriangle size={12} />
                            {rule.result.todos.length} item(s) need review
                          </div>
                        )}
                      </div>
                    )}

                    {rule.status === 'error' && (
                      <p className="text-sm text-red-400">{rule.error}</p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {bulkRules.length === 0 && (
            <div className="rounded-lg border bg-background p-12 text-center text-muted-foreground">
              <Upload size={48} className="mx-auto mb-4 opacity-20" />
              <p>Upload a file to start bulk conversion</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
