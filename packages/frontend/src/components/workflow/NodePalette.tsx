import { DragEvent } from 'react'
import {
  Zap,
  Calendar,
  Webhook,
  MousePointerClick,
  Globe,
  GitBranch,
  Repeat,
  Clock,
  Settings,
  Variable,
  Play,
} from 'lucide-react'
import type { WorkflowNodeType } from '../../api/pantherApi'

interface NodeTypeItem {
  type: WorkflowNodeType
  label: string
  description: string
  icon: typeof Zap
  category: 'trigger' | 'action' | 'logic' | 'utility'
}

const nodeTypes: NodeTypeItem[] = [
  // Triggers
  { type: 'trigger_alert', label: 'Alert Trigger', description: 'Triggered by alert match', icon: Zap, category: 'trigger' },
  { type: 'trigger_schedule', label: 'Schedule', description: 'Triggered on cron schedule', icon: Calendar, category: 'trigger' },
  { type: 'trigger_webhook', label: 'Webhook', description: 'Triggered by incoming webhook', icon: Webhook, category: 'trigger' },
  { type: 'trigger_manual', label: 'Manual', description: 'Triggered manually', icon: MousePointerClick, category: 'trigger' },
  // Actions
  { type: 'http_request', label: 'HTTP Request', description: 'Make HTTP API call', icon: Globe, category: 'action' },
  { type: 'connector_action', label: 'Connector', description: 'Execute connector action', icon: Play, category: 'action' },
  // Logic
  { type: 'condition', label: 'Condition', description: 'Branch based on condition', icon: GitBranch, category: 'logic' },
  { type: 'transform', label: 'Transform', description: 'Transform data', icon: Settings, category: 'logic' },
  { type: 'loop', label: 'Loop', description: 'Iterate over array', icon: Repeat, category: 'logic' },
  // Utility
  { type: 'delay', label: 'Delay', description: 'Wait for duration', icon: Clock, category: 'utility' },
  { type: 'set_variable', label: 'Set Variable', description: 'Set workflow variable', icon: Variable, category: 'utility' },
]

const categoryColors = {
  trigger: 'text-orange-400',
  action: 'text-cyan-400',
  logic: 'text-yellow-400',
  utility: 'text-gray-400',
}

interface NodePaletteProps {
  onDragStart?: (type: WorkflowNodeType) => void
}

export default function NodePalette({ onDragStart }: NodePaletteProps) {
  const handleDragStart = (event: DragEvent, nodeType: WorkflowNodeType) => {
    event.dataTransfer.setData('application/reactflow', nodeType)
    event.dataTransfer.effectAllowed = 'move'
    onDragStart?.(nodeType)
  }

  const groupedNodes = nodeTypes.reduce(
    (acc, node) => {
      if (!acc[node.category]) acc[node.category] = []
      acc[node.category].push(node)
      return acc
    },
    {} as Record<string, NodeTypeItem[]>
  )

  const categoryLabels = {
    trigger: 'Triggers',
    action: 'Actions',
    logic: 'Logic',
    utility: 'Utility',
  }

  return (
    <div className="w-64 bg-background border-r overflow-y-auto">
      <div className="p-4 border-b">
        <h2 className="font-semibold">Node Types</h2>
        <p className="text-xs text-muted-foreground">Drag nodes to canvas</p>
      </div>
      <div className="p-2 space-y-4">
        {(Object.keys(categoryLabels) as Array<keyof typeof categoryLabels>).map((category) => (
          <div key={category}>
            <h3 className={`text-xs font-semibold uppercase mb-2 px-2 ${categoryColors[category]}`}>
              {categoryLabels[category]}
            </h3>
            <div className="space-y-1">
              {groupedNodes[category]?.map((node) => {
                const Icon = node.icon
                return (
                  <div
                    key={node.type}
                    draggable
                    onDragStart={(e) => handleDragStart(e, node.type)}
                    className="flex items-center gap-2 p-2 rounded-md cursor-grab hover:bg-accent active:cursor-grabbing"
                  >
                    <Icon size={16} className="text-muted-foreground" />
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium">{node.label}</div>
                      <div className="text-xs text-muted-foreground truncate">{node.description}</div>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
