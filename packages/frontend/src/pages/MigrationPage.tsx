import { useState } from 'react'
import {
  ArrowRightLeft,
  FileCode,
  Upload,
  Wand2,
  Copy,
  Check,
  AlertCircle,
  ArrowRight,
  Loader2,
} from 'lucide-react'

// SIEM formats supported
const SIEM_FORMATS = [
  { id: 'sigma', name: 'Sigma', description: 'Universal detection format', color: 'bg-purple-500' },
  { id: 'spl', name: 'SPL', description: 'Splunk', color: 'bg-green-500' },
  { id: 'yaral', name: 'YARA-L', description: 'Google SecOps / Chronicle', color: 'bg-blue-500' },
  { id: 'kql', name: 'KQL', description: 'Microsoft Sentinel', color: 'bg-cyan-500' },
  { id: 'eql', name: 'EQL', description: 'Elastic Security', color: 'bg-yellow-500' },
  { id: 'esql', name: 'ES|QL', description: 'Elastic (new)', color: 'bg-orange-500' },
  { id: 'panther', name: 'Python', description: 'Panther SIEM', color: 'bg-red-500' },
] as const

type FormatId = typeof SIEM_FORMATS[number]['id']

const API_BASE = import.meta.env.VITE_API_BASE_URL || ''

export default function MigrationPage() {
  const [activeTab, setActiveTab] = useState<'converter' | 'bulk' | 'wizard'>('converter')

  // Converter state
  const [sourceFormat, setSourceFormat] = useState<FormatId>('spl')
  const [targetFormat, setTargetFormat] = useState<FormatId>('yaral')
  const [sourceCode, setSourceCode] = useState('')
  const [convertedCode, setConvertedCode] = useState('')
  const [isConverting, setIsConverting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  // Bulk import state
  const [bulkFiles, setBulkFiles] = useState<File[]>([])
  const [bulkResults, setBulkResults] = useState<Array<{ name: string; status: 'success' | 'error'; message?: string }>>([])
  const [isBulkProcessing, setIsBulkProcessing] = useState(false)

  const handleConvert = async () => {
    if (!sourceCode.trim()) {
      setError('Please enter source code to convert')
      return
    }

    if (sourceFormat === targetFormat) {
      setError('Source and target formats must be different')
      return
    }

    setIsConverting(true)
    setError(null)
    setConvertedCode('')

    try {
      const response = await fetch(`${API_BASE}/api/v1/migrate/convert`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source_format: sourceFormat,
          target_format: targetFormat,
          source_code: sourceCode,
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.detail || 'Conversion failed')
      }

      setConvertedCode(data.converted_code)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Conversion failed')
    } finally {
      setIsConverting(false)
    }
  }

  const handleCopy = async () => {
    await navigator.clipboard.writeText(convertedCode)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const swapFormats = () => {
    const temp = sourceFormat
    setSourceFormat(targetFormat)
    setTargetFormat(temp)
    setSourceCode(convertedCode)
    setConvertedCode('')
  }

  const handleBulkUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      setBulkFiles(Array.from(e.target.files))
      setBulkResults([])
    }
  }

  const processBulkImport = async () => {
    if (bulkFiles.length === 0) return

    setIsBulkProcessing(true)
    setBulkResults([])
    const results: typeof bulkResults = []

    for (const file of bulkFiles) {
      try {
        const content = await file.text()
        const response = await fetch(`${API_BASE}/api/v1/migrate/convert`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            source_format: sourceFormat,
            target_format: targetFormat,
            source_code: content,
          }),
        })

        if (response.ok) {
          results.push({ name: file.name, status: 'success' })
        } else {
          const data = await response.json()
          results.push({ name: file.name, status: 'error', message: data.detail })
        }
      } catch (err) {
        results.push({
          name: file.name,
          status: 'error',
          message: err instanceof Error ? err.message : 'Unknown error'
        })
      }
    }

    setBulkResults(results)
    setIsBulkProcessing(false)
  }

  const getFormatById = (id: FormatId) => SIEM_FORMATS.find(f => f.id === id)!

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">Migration Hub</h1>
        <p className="text-muted-foreground mt-1">
          Convert detection rules between SIEM platforms and migrate your security content
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b">
        <button
          onClick={() => setActiveTab('converter')}
          className={`flex items-center gap-2 px-4 py-2 border-b-2 transition-colors ${
            activeTab === 'converter'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          }`}
        >
          <ArrowRightLeft size={18} />
          Rule Converter
        </button>
        <button
          onClick={() => setActiveTab('bulk')}
          className={`flex items-center gap-2 px-4 py-2 border-b-2 transition-colors ${
            activeTab === 'bulk'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          }`}
        >
          <Upload size={18} />
          Bulk Import
        </button>
        <button
          onClick={() => setActiveTab('wizard')}
          className={`flex items-center gap-2 px-4 py-2 border-b-2 transition-colors ${
            activeTab === 'wizard'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          }`}
        >
          <Wand2 size={18} />
          Migration Wizard
        </button>
      </div>

      {/* Rule Converter Tab */}
      {activeTab === 'converter' && (
        <div className="space-y-6">
          {/* Format Selector */}
          <div className="flex items-center gap-4 p-4 rounded-lg border bg-card">
            <div className="flex-1">
              <label className="block text-sm font-medium mb-2">Source Format</label>
              <select
                value={sourceFormat}
                onChange={(e) => setSourceFormat(e.target.value as FormatId)}
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              >
                {SIEM_FORMATS.map((format) => (
                  <option key={format.id} value={format.id}>
                    {format.name} - {format.description}
                  </option>
                ))}
              </select>
            </div>

            <button
              onClick={swapFormats}
              className="p-2 rounded-md border hover:bg-accent transition-colors mt-6"
              title="Swap formats"
            >
              <ArrowRightLeft size={20} />
            </button>

            <div className="flex-1">
              <label className="block text-sm font-medium mb-2">Target Format</label>
              <select
                value={targetFormat}
                onChange={(e) => setTargetFormat(e.target.value as FormatId)}
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              >
                {SIEM_FORMATS.map((format) => (
                  <option key={format.id} value={format.id}>
                    {format.name} - {format.description}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Conversion Flow Indicator */}
          <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground">
            <span className={`px-2 py-1 rounded ${getFormatById(sourceFormat).color} text-white`}>
              {getFormatById(sourceFormat).name}
            </span>
            <ArrowRight size={16} />
            <span className="px-2 py-1 rounded bg-purple-500 text-white">Sigma</span>
            <ArrowRight size={16} />
            <span className={`px-2 py-1 rounded ${getFormatById(targetFormat).color} text-white`}>
              {getFormatById(targetFormat).name}
            </span>
            <span className="ml-2 text-xs">(via universal intermediate format)</span>
          </div>

          {/* Code Editors */}
          <div className="grid grid-cols-2 gap-4">
            {/* Source */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium flex items-center gap-2">
                  <FileCode size={16} />
                  Source ({getFormatById(sourceFormat).name})
                </label>
              </div>
              <textarea
                value={sourceCode}
                onChange={(e) => setSourceCode(e.target.value)}
                placeholder={getPlaceholder(sourceFormat)}
                className="w-full h-80 rounded-md border bg-background px-3 py-2 font-mono text-sm resize-none focus:outline-none focus:ring-2 focus:ring-primary"
              />
            </div>

            {/* Target */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium flex items-center gap-2">
                  <FileCode size={16} />
                  Converted ({getFormatById(targetFormat).name})
                </label>
                {convertedCode && (
                  <button
                    onClick={handleCopy}
                    className="flex items-center gap-1 px-2 py-1 text-xs rounded hover:bg-accent"
                  >
                    {copied ? <Check size={14} /> : <Copy size={14} />}
                    {copied ? 'Copied!' : 'Copy'}
                  </button>
                )}
              </div>
              <textarea
                value={convertedCode}
                readOnly
                placeholder="Converted code will appear here..."
                className="w-full h-80 rounded-md border bg-muted/50 px-3 py-2 font-mono text-sm resize-none"
              />
            </div>
          </div>

          {/* Error */}
          {error && (
            <div className="flex items-center gap-2 p-3 rounded-md bg-destructive/10 text-destructive">
              <AlertCircle size={16} />
              {error}
            </div>
          )}

          {/* Convert Button */}
          <div className="flex justify-center">
            <button
              onClick={handleConvert}
              disabled={isConverting || !sourceCode.trim()}
              className="flex items-center gap-2 px-6 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isConverting ? (
                <>
                  <Loader2 size={18} className="animate-spin" />
                  Converting...
                </>
              ) : (
                <>
                  <ArrowRightLeft size={18} />
                  Convert
                </>
              )}
            </button>
          </div>

          {/* Supported Conversions Matrix */}
          <div className="p-4 rounded-lg border bg-card">
            <h3 className="font-medium mb-3">Supported Conversions</h3>
            <div className="grid grid-cols-7 gap-1 text-xs">
              <div></div>
              {SIEM_FORMATS.map((f) => (
                <div key={f.id} className="text-center font-medium truncate" title={f.description}>
                  {f.name}
                </div>
              ))}
              {SIEM_FORMATS.map((source) => (
                <div key={source.id} className="contents">
                  <div className="font-medium truncate" title={source.description}>
                    {source.name}
                  </div>
                  {SIEM_FORMATS.map((target) => (
                    <div
                      key={`${source.id}-${target.id}`}
                      className={`text-center py-1 rounded ${
                        source.id === target.id
                          ? 'bg-muted text-muted-foreground'
                          : 'bg-green-500/20 text-green-500'
                      }`}
                    >
                      {source.id === target.id ? '-' : '✓'}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Bulk Import Tab */}
      {activeTab === 'bulk' && (
        <div className="space-y-6">
          <div className="p-6 rounded-lg border bg-card">
            <h3 className="font-medium mb-4">Bulk Rule Conversion</h3>
            <p className="text-sm text-muted-foreground mb-4">
              Upload multiple detection rule files to convert them all at once.
            </p>

            {/* Format Selection */}
            <div className="grid grid-cols-2 gap-4 mb-6">
              <div>
                <label className="block text-sm font-medium mb-2">Source Format</label>
                <select
                  value={sourceFormat}
                  onChange={(e) => setSourceFormat(e.target.value as FormatId)}
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                >
                  {SIEM_FORMATS.map((format) => (
                    <option key={format.id} value={format.id}>
                      {format.name} - {format.description}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">Target Format</label>
                <select
                  value={targetFormat}
                  onChange={(e) => setTargetFormat(e.target.value as FormatId)}
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                >
                  {SIEM_FORMATS.map((format) => (
                    <option key={format.id} value={format.id}>
                      {format.name} - {format.description}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* File Upload */}
            <div className="border-2 border-dashed rounded-lg p-8 text-center">
              <Upload size={48} className="mx-auto text-muted-foreground mb-4" />
              <p className="text-sm text-muted-foreground mb-4">
                Drag and drop rule files here, or click to browse
              </p>
              <input
                type="file"
                multiple
                accept=".yml,.yaml,.json,.txt,.spl,.kql,.eql,.py"
                onChange={handleBulkUpload}
                className="hidden"
                id="bulk-upload"
              />
              <label
                htmlFor="bulk-upload"
                className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md cursor-pointer hover:bg-primary/90"
              >
                <Upload size={16} />
                Select Files
              </label>
            </div>

            {/* Selected Files */}
            {bulkFiles.length > 0 && (
              <div className="mt-4">
                <h4 className="text-sm font-medium mb-2">Selected Files ({bulkFiles.length})</h4>
                <ul className="space-y-1 max-h-40 overflow-y-auto">
                  {bulkFiles.map((file, i) => (
                    <li key={i} className="text-sm text-muted-foreground flex items-center gap-2">
                      <FileCode size={14} />
                      {file.name}
                    </li>
                  ))}
                </ul>
                <button
                  onClick={processBulkImport}
                  disabled={isBulkProcessing}
                  className="mt-4 flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
                >
                  {isBulkProcessing ? (
                    <>
                      <Loader2 size={16} className="animate-spin" />
                      Processing...
                    </>
                  ) : (
                    <>
                      <ArrowRightLeft size={16} />
                      Convert All
                    </>
                  )}
                </button>
              </div>
            )}

            {/* Results */}
            {bulkResults.length > 0 && (
              <div className="mt-4">
                <h4 className="text-sm font-medium mb-2">Results</h4>
                <ul className="space-y-1">
                  {bulkResults.map((result, i) => (
                    <li
                      key={i}
                      className={`text-sm flex items-center gap-2 ${
                        result.status === 'success' ? 'text-green-500' : 'text-destructive'
                      }`}
                    >
                      {result.status === 'success' ? <Check size={14} /> : <AlertCircle size={14} />}
                      {result.name}
                      {result.message && <span className="text-muted-foreground">- {result.message}</span>}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Migration Wizard Tab */}
      {activeTab === 'wizard' && (
        <div className="space-y-6">
          <div className="p-6 rounded-lg border bg-card">
            <h3 className="font-medium mb-4">SIEM Migration Wizard</h3>
            <p className="text-sm text-muted-foreground mb-6">
              Step-by-step guide to migrate your detection rules from one SIEM to another.
            </p>

            <div className="grid grid-cols-3 gap-6">
              {/* Step 1 */}
              <div className="p-4 rounded-lg border bg-background">
                <div className="flex items-center gap-2 mb-3">
                  <span className="w-6 h-6 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-sm font-medium">
                    1
                  </span>
                  <h4 className="font-medium">Connect Source SIEM</h4>
                </div>
                <p className="text-sm text-muted-foreground mb-4">
                  Connect to your source SIEM to export detection rules automatically.
                </p>
                <a
                  href="/connectors"
                  className="text-sm text-primary hover:underline"
                >
                  Configure Connectors →
                </a>
              </div>

              {/* Step 2 */}
              <div className="p-4 rounded-lg border bg-background">
                <div className="flex items-center gap-2 mb-3">
                  <span className="w-6 h-6 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-sm font-medium">
                    2
                  </span>
                  <h4 className="font-medium">Convert Rules</h4>
                </div>
                <p className="text-sm text-muted-foreground mb-4">
                  Convert detection rules to your target SIEM format using Sigma as intermediate.
                </p>
                <button
                  onClick={() => setActiveTab('converter')}
                  className="text-sm text-primary hover:underline"
                >
                  Open Converter →
                </button>
              </div>

              {/* Step 3 */}
              <div className="p-4 rounded-lg border bg-background">
                <div className="flex items-center gap-2 mb-3">
                  <span className="w-6 h-6 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-sm font-medium">
                    3
                  </span>
                  <h4 className="font-medium">Deploy to Target</h4>
                </div>
                <p className="text-sm text-muted-foreground mb-4">
                  Push converted rules to your target SIEM through the connector.
                </p>
                <a
                  href="/connectors"
                  className="text-sm text-primary hover:underline"
                >
                  Deploy Rules →
                </a>
              </div>
            </div>

            {/* Migration Paths */}
            <div className="mt-8">
              <h4 className="font-medium mb-4">Common Migration Paths</h4>
              <div className="grid grid-cols-2 gap-4">
                {[
                  { from: 'Splunk', to: 'Google SecOps', fromId: 'spl', toId: 'yaral' },
                  { from: 'Splunk', to: 'Microsoft Sentinel', fromId: 'spl', toId: 'kql' },
                  { from: 'Microsoft Sentinel', to: 'Google SecOps', fromId: 'kql', toId: 'yaral' },
                  { from: 'Elastic', to: 'Panther', fromId: 'eql', toId: 'panther' },
                ].map((path) => (
                  <button
                    key={`${path.fromId}-${path.toId}`}
                    onClick={() => {
                      setSourceFormat(path.fromId as FormatId)
                      setTargetFormat(path.toId as FormatId)
                      setActiveTab('converter')
                    }}
                    className="flex items-center gap-3 p-3 rounded-lg border hover:bg-accent transition-colors text-left"
                  >
                    <span className="font-medium">{path.from}</span>
                    <ArrowRight size={16} className="text-muted-foreground" />
                    <span className="font-medium">{path.to}</span>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function getPlaceholder(format: FormatId): string {
  const placeholders: Record<FormatId, string> = {
    sigma: `title: Suspicious Process Creation
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection`,
    spl: `index=windows sourcetype=WinEventLog:Security EventCode=4688
| where like(NewProcessName, "%powershell.exe")
| where like(CommandLine, "%-enc%")
| table _time, ComputerName, User, NewProcessName, CommandLine`,
    yaral: `rule suspicious_powershell_execution {
  meta:
    author = "Security Team"
    description = "Detects encoded PowerShell execution"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.full_path = /powershell\\.exe$/
    $e.target.process.command_line = /\\-enc/
  condition:
    $e
}`,
    kql: `SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
| where CommandLine contains "-enc"
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine`,
    eql: `process where process.name == "powershell.exe" and process.command_line : "*-enc*"`,
    esql: `FROM logs-windows.*
| WHERE process.name == "powershell.exe" AND process.command_line LIKE "*-enc*"
| KEEP @timestamp, host.name, user.name, process.name, process.command_line`,
    panther: `def rule(event):
    if event.get("process_name", "").endswith("powershell.exe"):
        command_line = event.get("command_line", "")
        if "-enc" in command_line.lower():
            return True
    return False

def title(event):
    return f"Suspicious PowerShell on {event.get('hostname', 'unknown')}"`,
  }
  return placeholders[format] || ''
}
