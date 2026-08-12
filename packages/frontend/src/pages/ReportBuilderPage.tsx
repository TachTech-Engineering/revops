import { useState } from 'react'
import {
  FileBarChart,
  Plus,
  Play,
  Download,
  RefreshCw,
  Calendar,
  Clock,
  Trash2,
  Edit,
  Copy,
  Eye,
  Mail,
  BarChart3,
  PieChart,
  LineChart,
  Table,
  Save,
} from 'lucide-react'

interface ReportTemplate {
  id: string
  name: string
  description: string
  type: 'alert' | 'incident' | 'compliance' | 'custom'
  schedule?: {
    frequency: 'daily' | 'weekly' | 'monthly'
    time: string
    recipients: string[]
  }
  sections: ReportSection[]
  lastGenerated?: string
  createdBy: string
}

interface ReportSection {
  id: string
  title: string
  type: 'chart' | 'table' | 'metric' | 'text'
  chartType?: 'bar' | 'pie' | 'line'
  dataSource: string
  filters?: Record<string, string>
}

const mockTemplates: ReportTemplate[] = [
  {
    id: '1',
    name: 'Weekly Security Summary',
    description: 'Overview of security alerts, incidents, and trends',
    type: 'alert',
    schedule: {
      frequency: 'weekly',
      time: '09:00',
      recipients: ['security-team@company.com', 'ciso@company.com'],
    },
    sections: [
      { id: '1', title: 'Alert Volume', type: 'chart', chartType: 'line', dataSource: 'alerts' },
      { id: '2', title: 'Alerts by Severity', type: 'chart', chartType: 'pie', dataSource: 'alerts' },
      { id: '3', title: 'Top Alerting Rules', type: 'table', dataSource: 'rules' },
    ],
    lastGenerated: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    createdBy: 'Security Team',
  },
  {
    id: '2',
    name: 'Monthly Compliance Report',
    description: 'Compliance posture across all frameworks',
    type: 'compliance',
    schedule: {
      frequency: 'monthly',
      time: '08:00',
      recipients: ['compliance@company.com', 'audit@company.com'],
    },
    sections: [
      { id: '1', title: 'Overall Compliance Score', type: 'metric', dataSource: 'compliance' },
      { id: '2', title: 'Framework Coverage', type: 'chart', chartType: 'bar', dataSource: 'compliance' },
      { id: '3', title: 'Control Gaps', type: 'table', dataSource: 'compliance' },
    ],
    lastGenerated: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString(),
    createdBy: 'Compliance Team',
  },
  {
    id: '3',
    name: 'Executive Dashboard',
    description: 'High-level metrics for leadership',
    type: 'custom',
    sections: [
      { id: '1', title: 'Key Metrics', type: 'metric', dataSource: 'alerts' },
      { id: '2', title: 'MTTR Trend', type: 'chart', chartType: 'line', dataSource: 'incidents' },
      { id: '3', title: 'Risk Summary', type: 'text', dataSource: 'custom' },
    ],
    createdBy: 'CISO',
  },
]

const chartTypeIcons = {
  bar: BarChart3,
  pie: PieChart,
  line: LineChart,
}

export default function ReportBuilderPage() {
  const [templates, setTemplates] = useState(mockTemplates)
  const [showBuilder, setShowBuilder] = useState(false)
  const [isGenerating, setIsGenerating] = useState<string | null>(null)
  const [previewTemplate, setPreviewTemplate] = useState<ReportTemplate | null>(null)
  const [editingTemplate, setEditingTemplate] = useState<ReportTemplate | null>(null)

  const [newReport, setNewReport] = useState<{
    name: string
    description: string
    type: 'alert' | 'incident' | 'compliance' | 'custom'
    sections: ReportSection[]
    scheduleEnabled: boolean
    schedule: {
      frequency: 'daily' | 'weekly' | 'monthly'
      time: string
      recipients: string[]
    }
  }>({
    name: '',
    description: '',
    type: 'custom',
    sections: [],
    scheduleEnabled: false,
    schedule: {
      frequency: 'weekly',
      time: '09:00',
      recipients: [] as string[],
    },
  })
  const [newRecipient, setNewRecipient] = useState('')

  const handleGenerateReport = async (templateId: string) => {
    setIsGenerating(templateId)
    await new Promise((resolve) => setTimeout(resolve, 3000))
    setIsGenerating(null)
  }

  const handleDuplicateTemplate = (template: ReportTemplate) => {
    const duplicate: ReportTemplate = {
      ...template,
      id: Date.now().toString(),
      name: `${template.name} (Copy)`,
      schedule: undefined,
      lastGenerated: undefined,
    }
    setTemplates([...templates, duplicate])
  }

  const handleDeleteTemplate = (templateId: string) => {
    if (confirm('Are you sure you want to delete this report template?')) {
      setTemplates(templates.filter((t) => t.id !== templateId))
    }
  }

  const handleEditTemplate = (template: ReportTemplate) => {
    setEditingTemplate(template)
    setNewReport({
      name: template.name,
      description: template.description,
      type: template.type,
      sections: [...template.sections],
      scheduleEnabled: !!template.schedule,
      schedule: template.schedule ? {
        frequency: template.schedule.frequency,
        time: template.schedule.time,
        recipients: [...template.schedule.recipients],
      } : {
        frequency: 'weekly',
        time: '09:00',
        recipients: [],
      },
    })
    setShowBuilder(true)
  }

  const handleSaveReport = () => {
    const scheduleData = newReport.scheduleEnabled && newReport.schedule.recipients.length > 0
      ? {
          frequency: newReport.schedule.frequency,
          time: newReport.schedule.time,
          recipients: newReport.schedule.recipients,
        }
      : undefined

    if (editingTemplate) {
      // Update existing template
      setTemplates(templates.map(t =>
        t.id === editingTemplate.id
          ? {
              ...t,
              name: newReport.name,
              description: newReport.description,
              type: newReport.type,
              sections: newReport.sections,
              schedule: scheduleData,
            }
          : t
      ))
    } else {
      // Create new template
      const newTemplate: ReportTemplate = {
        id: Date.now().toString(),
        name: newReport.name,
        description: newReport.description,
        type: newReport.type,
        sections: newReport.sections,
        schedule: scheduleData,
        createdBy: 'Current User',
      }
      setTemplates([...templates, newTemplate])
    }
    handleCloseBuilder()
  }

  const handleCloseBuilder = () => {
    setShowBuilder(false)
    setEditingTemplate(null)
    setNewReport({
      name: '',
      description: '',
      type: 'custom',
      sections: [],
      scheduleEnabled: false,
      schedule: { frequency: 'weekly', time: '09:00', recipients: [] },
    })
    setNewRecipient('')
  }

  const handlePreview = (template: ReportTemplate) => {
    setPreviewTemplate(template)
  }

  const handleDownload = async (template: ReportTemplate) => {
    // Simulate report generation and download
    const reportContent = {
      title: template.name,
      description: template.description,
      generatedAt: new Date().toISOString(),
      sections: template.sections.map(s => ({
        title: s.title,
        type: s.type,
        data: `Sample data for ${s.title}`,
      })),
    }

    const blob = new Blob([JSON.stringify(reportContent, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${template.name.toLowerCase().replace(/\s+/g, '-')}-${new Date().toISOString().split('T')[0]}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const handleAddSection = () => {
    const newSection: ReportSection = {
      id: Date.now().toString(),
      title: `Section ${newReport.sections.length + 1}`,
      type: 'chart',
      chartType: 'bar',
      dataSource: 'alerts',
    }
    setNewReport({ ...newReport, sections: [...newReport.sections, newSection] })
  }

  const handleRemoveSection = (sectionId: string) => {
    setNewReport({ ...newReport, sections: newReport.sections.filter(s => s.id !== sectionId) })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <FileBarChart className="text-primary" />
            Report Builder
          </h1>
          <p className="text-muted-foreground mt-1">
            Create and manage custom security reports
          </p>
        </div>
        <button
          onClick={() => setShowBuilder(true)}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
        >
          <Plus size={16} />
          New Report
        </button>
      </div>

      {/* Report Builder Modal */}
      {showBuilder && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-semibold">
                {editingTemplate ? 'Edit Report' : 'Create New Report'}
              </h2>
              <button
                onClick={handleCloseBuilder}
                className="p-2 hover:bg-accent rounded-md"
              >
                ×
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Report Name</label>
                <input
                  type="text"
                  value={newReport.name}
                  onChange={(e) => setNewReport({ ...newReport, name: e.target.value })}
                  placeholder="Weekly Security Summary"
                  className="w-full px-3 py-2 bg-background border rounded-md"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">Description</label>
                <textarea
                  value={newReport.description}
                  onChange={(e) => setNewReport({ ...newReport, description: e.target.value })}
                  placeholder="Brief description of the report"
                  className="w-full px-3 py-2 bg-background border rounded-md h-20 resize-none"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">Report Type</label>
                <select
                  value={newReport.type}
                  onChange={(e) => setNewReport({ ...newReport, type: e.target.value as typeof newReport.type })}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                >
                  <option value="alert">Alert Report</option>
                  <option value="incident">Incident Report</option>
                  <option value="compliance">Compliance Report</option>
                  <option value="custom">Custom Report</option>
                </select>
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="text-sm font-medium">Report Sections</label>
                  <button
                    onClick={handleAddSection}
                    className="text-sm text-primary hover:underline flex items-center gap-1"
                  >
                    <Plus size={12} />
                    Add Section
                  </button>
                </div>
                <div className="space-y-2 bg-muted/30 rounded-lg p-3 min-h-[100px]">
                  {newReport.sections.length === 0 ? (
                    <p className="text-sm text-muted-foreground text-center py-4">
                      Add sections to build your report
                    </p>
                  ) : (
                    newReport.sections.map((section, index) => (
                      <div key={section.id} className="p-2 bg-background rounded flex items-center justify-between gap-2">
                        <input
                          type="text"
                          value={section.title}
                          onChange={(e) => {
                            const updated = [...newReport.sections]
                            updated[index] = { ...updated[index], title: e.target.value }
                            setNewReport({ ...newReport, sections: updated })
                          }}
                          className="flex-1 px-2 py-1 bg-muted border rounded text-sm"
                        />
                        <select
                          value={section.type}
                          onChange={(e) => {
                            const updated = [...newReport.sections]
                            updated[index] = { ...updated[index], type: e.target.value as ReportSection['type'] }
                            setNewReport({ ...newReport, sections: updated })
                          }}
                          className="px-2 py-1 bg-muted border rounded text-sm"
                        >
                          <option value="chart">Chart</option>
                          <option value="table">Table</option>
                          <option value="metric">Metric</option>
                          <option value="text">Text</option>
                        </select>
                        {section.type === 'chart' && (
                          <select
                            value={section.chartType || 'bar'}
                            onChange={(e) => {
                              const updated = [...newReport.sections]
                              updated[index] = { ...updated[index], chartType: e.target.value as ReportSection['chartType'] }
                              setNewReport({ ...newReport, sections: updated })
                            }}
                            className="px-2 py-1 bg-muted border rounded text-sm"
                          >
                            <option value="bar">Bar</option>
                            <option value="pie">Pie</option>
                            <option value="line">Line</option>
                          </select>
                        )}
                        <button
                          onClick={() => handleRemoveSection(section.id)}
                          className="text-red-400 hover:text-red-300 p-1"
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Schedule Section */}
              <div className="border-t pt-4">
                <div className="flex items-center gap-2 mb-3">
                  <input
                    type="checkbox"
                    id="scheduleEnabled"
                    checked={newReport.scheduleEnabled}
                    onChange={(e) => setNewReport({ ...newReport, scheduleEnabled: e.target.checked })}
                    className="rounded"
                  />
                  <label htmlFor="scheduleEnabled" className="text-sm font-medium flex items-center gap-2">
                    <Calendar size={14} />
                    Enable Scheduled Delivery
                  </label>
                </div>

                {newReport.scheduleEnabled && (
                  <div className="space-y-3 ml-6 p-3 bg-muted/30 rounded-lg">
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="block text-xs font-medium mb-1">Frequency</label>
                        <select
                          value={newReport.schedule.frequency}
                          onChange={(e) => setNewReport({
                            ...newReport,
                            schedule: { ...newReport.schedule, frequency: e.target.value as 'daily' | 'weekly' | 'monthly' }
                          })}
                          className="w-full px-2 py-1.5 bg-background border rounded-md text-sm"
                        >
                          <option value="daily">Daily</option>
                          <option value="weekly">Weekly</option>
                          <option value="monthly">Monthly</option>
                        </select>
                      </div>
                      <div>
                        <label className="block text-xs font-medium mb-1">Time</label>
                        <input
                          type="time"
                          value={newReport.schedule.time}
                          onChange={(e) => setNewReport({
                            ...newReport,
                            schedule: { ...newReport.schedule, time: e.target.value }
                          })}
                          className="w-full px-2 py-1.5 bg-background border rounded-md text-sm"
                        />
                      </div>
                    </div>

                    <div>
                      <label className="block text-xs font-medium mb-1">Recipients</label>
                      <div className="flex gap-2 mb-2">
                        <input
                          type="email"
                          value={newRecipient}
                          onChange={(e) => setNewRecipient(e.target.value)}
                          placeholder="email@example.com"
                          className="flex-1 px-2 py-1.5 bg-background border rounded-md text-sm"
                          onKeyDown={(e) => {
                            if (e.key === 'Enter' && newRecipient && newRecipient.includes('@')) {
                              e.preventDefault()
                              if (!newReport.schedule.recipients.includes(newRecipient)) {
                                setNewReport({
                                  ...newReport,
                                  schedule: {
                                    ...newReport.schedule,
                                    recipients: [...newReport.schedule.recipients, newRecipient]
                                  }
                                })
                              }
                              setNewRecipient('')
                            }
                          }}
                        />
                        <button
                          type="button"
                          onClick={() => {
                            if (newRecipient && newRecipient.includes('@') && !newReport.schedule.recipients.includes(newRecipient)) {
                              setNewReport({
                                ...newReport,
                                schedule: {
                                  ...newReport.schedule,
                                  recipients: [...newReport.schedule.recipients, newRecipient]
                                }
                              })
                              setNewRecipient('')
                            }
                          }}
                          className="px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm hover:bg-primary/90"
                        >
                          Add
                        </button>
                      </div>
                      {newReport.schedule.recipients.length > 0 ? (
                        <div className="flex flex-wrap gap-2">
                          {newReport.schedule.recipients.map((email, index) => (
                            <span
                              key={index}
                              className="flex items-center gap-1 px-2 py-1 bg-background border rounded text-xs"
                            >
                              <Mail size={10} />
                              {email}
                              <button
                                onClick={() => setNewReport({
                                  ...newReport,
                                  schedule: {
                                    ...newReport.schedule,
                                    recipients: newReport.schedule.recipients.filter((_, i) => i !== index)
                                  }
                                })}
                                className="ml-1 text-red-400 hover:text-red-300"
                              >
                                ×
                              </button>
                            </span>
                          ))}
                        </div>
                      ) : (
                        <p className="text-xs text-muted-foreground">No recipients added yet</p>
                      )}
                    </div>
                  </div>
                )}
              </div>

              <div className="flex justify-end gap-2 pt-4 border-t">
                <button
                  onClick={handleCloseBuilder}
                  className="px-4 py-2 border rounded-md hover:bg-accent"
                >
                  Cancel
                </button>
                <button
                  onClick={handleSaveReport}
                  disabled={!newReport.name}
                  className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
                >
                  <Save size={14} />
                  {editingTemplate ? 'Save Changes' : 'Create Report'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Preview Modal */}
      {previewTemplate && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card rounded-lg p-6 max-w-4xl w-full mx-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className="text-xl font-semibold">{previewTemplate.name}</h2>
                <p className="text-sm text-muted-foreground">{previewTemplate.description}</p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleDownload(previewTemplate)}
                  className="flex items-center gap-2 px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm hover:bg-primary/90"
                >
                  <Download size={14} />
                  Download
                </button>
                <button
                  onClick={() => setPreviewTemplate(null)}
                  className="p-2 hover:bg-accent rounded-md"
                >
                  ×
                </button>
              </div>
            </div>

            <div className="space-y-6">
              {previewTemplate.sections.map((section) => {
                const ChartIcon = section.chartType
                  ? chartTypeIcons[section.chartType]
                  : section.type === 'table'
                  ? Table
                  : BarChart3

                return (
                  <div key={section.id} className="border rounded-lg p-4">
                    <h3 className="font-medium mb-3 flex items-center gap-2">
                      <ChartIcon size={16} className="text-muted-foreground" />
                      {section.title}
                    </h3>
                    <div className="bg-muted/30 rounded-lg p-6 min-h-[150px] flex items-center justify-center">
                      {section.type === 'chart' && section.chartType === 'bar' && (
                        <div className="flex items-end gap-2 h-24">
                          {[40, 65, 45, 80, 55, 70, 50].map((h, i) => (
                            <div
                              key={i}
                              className="w-8 bg-primary rounded-t"
                              style={{ height: `${h}%` }}
                            />
                          ))}
                        </div>
                      )}
                      {section.type === 'chart' && section.chartType === 'pie' && (
                        <div className="w-24 h-24 rounded-full bg-gradient-to-br from-primary via-yellow-500 to-red-500" />
                      )}
                      {section.type === 'chart' && section.chartType === 'line' && (
                        <svg viewBox="0 0 100 50" className="w-48 h-24">
                          <polyline
                            fill="none"
                            stroke="currentColor"
                            strokeWidth="2"
                            className="text-primary"
                            points="0,40 15,35 30,25 45,30 60,15 75,20 90,10 100,15"
                          />
                        </svg>
                      )}
                      {section.type === 'table' && (
                        <div className="w-full">
                          <div className="grid grid-cols-4 gap-2 text-sm">
                            <div className="font-medium p-2 bg-muted rounded">Name</div>
                            <div className="font-medium p-2 bg-muted rounded">Count</div>
                            <div className="font-medium p-2 bg-muted rounded">Status</div>
                            <div className="font-medium p-2 bg-muted rounded">Trend</div>
                            {[1, 2, 3].map((row) => (
                              <>
                                <div key={`name-${row}`} className="p-2">Sample {row}</div>
                                <div key={`count-${row}`} className="p-2">{row * 12}</div>
                                <div key={`status-${row}`} className="p-2">Active</div>
                                <div key={`trend-${row}`} className="p-2 text-green-400">↑ {row * 5}%</div>
                              </>
                            ))}
                          </div>
                        </div>
                      )}
                      {section.type === 'metric' && (
                        <div className="text-center">
                          <div className="text-4xl font-bold text-primary">87%</div>
                          <div className="text-sm text-muted-foreground mt-1">Sample Metric</div>
                        </div>
                      )}
                      {section.type === 'text' && (
                        <p className="text-muted-foreground text-sm">
                          This section contains customizable text content for your report.
                          It can include summaries, analysis, or any other narrative information.
                        </p>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>

            <div className="mt-6 pt-4 border-t text-xs text-muted-foreground">
              <p>Report preview generated on {new Date().toLocaleString()}</p>
              {previewTemplate.lastGenerated && (
                <p>Last generated: {new Date(previewTemplate.lastGenerated).toLocaleString()}</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Template List */}
      <div className="grid gap-4">
        {templates.map((template) => (
          <div key={template.id} className="bg-card rounded-lg border">
            <div className="p-4 flex items-start justify-between">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 rounded-lg bg-primary/20 flex items-center justify-center">
                  <FileBarChart className="text-primary" size={24} />
                </div>
                <div>
                  <h3 className="font-semibold">{template.name}</h3>
                  <p className="text-sm text-muted-foreground">{template.description}</p>
                  <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                    <span className="capitalize px-2 py-0.5 bg-muted rounded">
                      {template.type}
                    </span>
                    <span>{template.sections.length} sections</span>
                    <span>Created by {template.createdBy}</span>
                    {template.lastGenerated && (
                      <span>
                        Last generated: {new Date(template.lastGenerated).toLocaleDateString()}
                      </span>
                    )}
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2">
                {template.schedule && (
                  <span className="flex items-center gap-1 px-2 py-1 bg-green-500/20 text-green-400 rounded text-xs">
                    <Clock size={10} />
                    {template.schedule.frequency}
                  </span>
                )}
                <button
                  onClick={() => handleGenerateReport(template.id)}
                  disabled={isGenerating === template.id}
                  className="flex items-center gap-2 px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm hover:bg-primary/90 disabled:opacity-50"
                >
                  {isGenerating === template.id ? (
                    <>
                      <RefreshCw size={14} className="animate-spin" />
                      Generating...
                    </>
                  ) : (
                    <>
                      <Play size={14} />
                      Generate
                    </>
                  )}
                </button>
                <button
                  onClick={() => handlePreview(template)}
                  className="p-2 hover:bg-accent rounded-md"
                  title="Preview"
                >
                  <Eye size={14} />
                </button>
                <button
                  onClick={() => handleDownload(template)}
                  className="p-2 hover:bg-accent rounded-md"
                  title="Download"
                >
                  <Download size={14} />
                </button>
                <button
                  onClick={() => handleDuplicateTemplate(template)}
                  className="p-2 hover:bg-accent rounded-md"
                  title="Duplicate"
                >
                  <Copy size={14} />
                </button>
                <button
                  onClick={() => handleEditTemplate(template)}
                  className="p-2 hover:bg-accent rounded-md"
                  title="Edit"
                >
                  <Edit size={14} />
                </button>
                <button
                  onClick={() => handleDeleteTemplate(template.id)}
                  className="p-2 hover:bg-accent rounded-md text-red-400"
                  title="Delete"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            </div>

            {/* Sections Preview */}
            <div className="px-4 pb-4">
              <div className="flex items-center gap-2 overflow-x-auto">
                {template.sections.map((section) => {
                  const ChartIcon = section.chartType
                    ? chartTypeIcons[section.chartType]
                    : section.type === 'table'
                    ? Table
                    : BarChart3
                  return (
                    <div
                      key={section.id}
                      className="flex items-center gap-2 px-3 py-1.5 bg-muted rounded text-sm whitespace-nowrap"
                    >
                      <ChartIcon size={12} className="text-muted-foreground" />
                      {section.title}
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Schedule Info */}
            {template.schedule && (
              <div className="px-4 pb-4 pt-2 border-t">
                <div className="flex items-center gap-4 text-xs text-muted-foreground">
                  <span className="flex items-center gap-1">
                    <Calendar size={12} />
                    {template.schedule.frequency} at {template.schedule.time}
                  </span>
                  <span className="flex items-center gap-1">
                    <Mail size={12} />
                    {template.schedule.recipients.length} recipients
                  </span>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {templates.length === 0 && (
        <div className="text-center py-12">
          <FileBarChart className="mx-auto text-muted-foreground mb-4" size={48} />
          <p className="text-muted-foreground">No report templates yet</p>
          <button
            onClick={() => setShowBuilder(true)}
            className="mt-4 text-primary hover:underline"
          >
            Create your first report
          </button>
        </div>
      )}
    </div>
  )
}
