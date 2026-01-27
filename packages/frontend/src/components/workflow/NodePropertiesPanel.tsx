import { useEffect, useState } from 'react'
import { X } from 'lucide-react'
import type { Node } from 'reactflow'
import type { WorkflowNodeData } from './WorkflowNode'
import type { WorkflowNodeType } from '../../api/pantherApi'

interface NodePropertiesPanelProps {
  node: Node<WorkflowNodeData> | null
  onClose: () => void
  onUpdate: (nodeId: string, data: Partial<WorkflowNodeData>) => void
}

const nodeConfigSchema: Record<WorkflowNodeType, { fields: ConfigField[] }> = {
  trigger_alert: {
    fields: [
      { key: 'severities', label: 'Severities', type: 'multiselect', options: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] },
      { key: 'rule_ids', label: 'Rule IDs (comma-separated)', type: 'text' },
      { key: 'title_pattern', label: 'Title Pattern (regex)', type: 'text' },
    ],
  },
  trigger_schedule: {
    fields: [
      { key: 'cron', label: 'Cron Expression', type: 'text', placeholder: '0 * * * *' },
      { key: 'timezone', label: 'Timezone', type: 'text', placeholder: 'UTC' },
    ],
  },
  trigger_webhook: {
    fields: [
      { key: 'path', label: 'Webhook Path', type: 'text', placeholder: '/webhook/my-workflow' },
      { key: 'secret', label: 'Webhook Secret', type: 'password' },
    ],
  },
  trigger_manual: {
    fields: [],
  },
  http_request: {
    fields: [
      { key: 'method', label: 'Method', type: 'select', options: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] },
      { key: 'url', label: 'URL', type: 'text', placeholder: 'https://api.example.com/endpoint' },
      { key: 'headers', label: 'Headers (JSON)', type: 'textarea', placeholder: '{"Authorization": "Bearer {{variables.token}}"}' },
      { key: 'body', label: 'Body (JSON)', type: 'textarea', placeholder: '{"key": "{{trigger.alert.id}}"}' },
    ],
  },
  connector_action: {
    fields: [
      { key: 'connector_id', label: 'Connector ID', type: 'text' },
      { key: 'action', label: 'Action', type: 'text' },
      { key: 'action_config', label: 'Action Config (JSON)', type: 'textarea' },
    ],
  },
  condition: {
    fields: [
      { key: 'expression', label: 'Expression', type: 'text', placeholder: '{{trigger.alert.severity}} == "CRITICAL"' },
    ],
  },
  transform: {
    fields: [
      { key: 'expression', label: 'Transform Expression', type: 'textarea', placeholder: '{"transformed": {{steps.prev.output | json}}}' },
    ],
  },
  delay: {
    fields: [
      { key: 'seconds', label: 'Delay (seconds)', type: 'number', placeholder: '60' },
    ],
  },
  loop: {
    fields: [
      { key: 'items', label: 'Items Expression', type: 'text', placeholder: '{{steps.http.output.data}}' },
      { key: 'item_variable', label: 'Item Variable Name', type: 'text', placeholder: 'item' },
    ],
  },
  set_variable: {
    fields: [
      { key: 'variables', label: 'Variables (JSON)', type: 'textarea', placeholder: '{"my_var": "{{trigger.alert.title}}"}' },
    ],
  },
}

interface ConfigField {
  key: string
  label: string
  type: 'text' | 'textarea' | 'number' | 'select' | 'multiselect' | 'password'
  placeholder?: string
  options?: string[]
}

export default function NodePropertiesPanel({ node, onClose, onUpdate }: NodePropertiesPanelProps) {
  const [label, setLabel] = useState('')
  const [config, setConfig] = useState<Record<string, unknown>>({})
  const [onError, setOnError] = useState('fail')

  useEffect(() => {
    if (node) {
      setLabel(node.data.label)
      setConfig(node.data.config || {})
      setOnError(node.data.on_error || 'fail')
    }
  }, [node])

  if (!node) return null

  const schema = nodeConfigSchema[node.data.node_type] || { fields: [] }

  const handleLabelChange = (value: string) => {
    setLabel(value)
    onUpdate(node.id, { label: value })
  }

  const handleConfigChange = (key: string, value: unknown) => {
    const newConfig = { ...config, [key]: value }
    setConfig(newConfig)
    onUpdate(node.id, { config: newConfig })
  }

  const handleOnErrorChange = (value: string) => {
    setOnError(value)
    onUpdate(node.id, { on_error: value })
  }

  return (
    <div className="w-80 bg-background border-l overflow-y-auto">
      <div className="p-4 border-b flex items-center justify-between">
        <h2 className="font-semibold">Node Properties</h2>
        <button onClick={onClose} className="p-1 hover:bg-accent rounded">
          <X size={18} />
        </button>
      </div>
      <div className="p-4 space-y-4">
        {/* Label */}
        <div>
          <label className="block text-sm font-medium mb-1">Label</label>
          <input
            type="text"
            value={label}
            onChange={(e) => handleLabelChange(e.target.value)}
            className="w-full px-3 py-2 rounded-md border bg-background text-sm"
          />
        </div>

        {/* Node Type (read-only) */}
        <div>
          <label className="block text-sm font-medium mb-1">Type</label>
          <div className="px-3 py-2 rounded-md bg-muted text-sm text-muted-foreground">
            {node.data.node_type.replace(/_/g, ' ')}
          </div>
        </div>

        {/* Dynamic Config Fields */}
        {schema.fields.map((field) => (
          <div key={field.key}>
            <label className="block text-sm font-medium mb-1">{field.label}</label>
            {field.type === 'textarea' ? (
              <textarea
                value={String(config[field.key] || '')}
                onChange={(e) => handleConfigChange(field.key, e.target.value)}
                className="w-full px-3 py-2 rounded-md border bg-background text-sm font-mono"
                rows={4}
                placeholder={field.placeholder}
              />
            ) : field.type === 'select' ? (
              <select
                value={String(config[field.key] || '')}
                onChange={(e) => handleConfigChange(field.key, e.target.value)}
                className="w-full px-3 py-2 rounded-md border bg-background text-sm"
              >
                <option value="">Select...</option>
                {field.options?.map((opt) => (
                  <option key={opt} value={opt}>
                    {opt}
                  </option>
                ))}
              </select>
            ) : field.type === 'multiselect' ? (
              <div className="space-y-1">
                {field.options?.map((opt) => (
                  <label key={opt} className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={((config[field.key] as string[]) || []).includes(opt)}
                      onChange={(e) => {
                        const current = (config[field.key] as string[]) || []
                        const updated = e.target.checked
                          ? [...current, opt]
                          : current.filter((v) => v !== opt)
                        handleConfigChange(field.key, updated)
                      }}
                      className="rounded"
                    />
                    <span className="text-sm">{opt}</span>
                  </label>
                ))}
              </div>
            ) : field.type === 'number' ? (
              <input
                type="number"
                value={String(config[field.key] || '')}
                onChange={(e) => handleConfigChange(field.key, parseInt(e.target.value) || 0)}
                className="w-full px-3 py-2 rounded-md border bg-background text-sm"
                placeholder={field.placeholder}
              />
            ) : (
              <input
                type={field.type === 'password' ? 'password' : 'text'}
                value={String(config[field.key] || '')}
                onChange={(e) => handleConfigChange(field.key, e.target.value)}
                className="w-full px-3 py-2 rounded-md border bg-background text-sm"
                placeholder={field.placeholder}
              />
            )}
          </div>
        ))}

        {/* Error Handling */}
        <div>
          <label className="block text-sm font-medium mb-1">On Error</label>
          <select
            value={onError}
            onChange={(e) => handleOnErrorChange(e.target.value)}
            className="w-full px-3 py-2 rounded-md border bg-background text-sm"
          >
            <option value="fail">Fail Workflow</option>
            <option value="continue">Continue</option>
            <option value="goto_node">Go to Error Handler</option>
          </select>
        </div>

        {/* Template Variables Help */}
        <div className="p-3 rounded-md bg-muted text-xs">
          <div className="font-medium mb-1">Template Variables</div>
          <div className="text-muted-foreground space-y-0.5">
            <div><code>{'{{trigger.alert.id}}'}</code> - Alert ID</div>
            <div><code>{'{{steps.node_key.output}}'}</code> - Step output</div>
            <div><code>{'{{variables.name}}'}</code> - Variable</div>
            <div><code>{'{{loop.item}}'}</code> - Loop item</div>
          </div>
        </div>
      </div>
    </div>
  )
}
