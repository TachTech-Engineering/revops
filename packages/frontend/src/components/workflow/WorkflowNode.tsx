import { memo } from 'react'
import { Handle, Position, NodeProps } from 'reactflow'
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
import { cn } from '../../lib/utils'
import type { WorkflowNodeType } from '../../api/pantherApi'

const nodeTypeConfig: Record<
  WorkflowNodeType,
  { icon: typeof Zap; color: string; category: string }
> = {
  trigger_alert: { icon: Zap, color: 'border-orange-500 bg-orange-500/10', category: 'trigger' },
  trigger_schedule: { icon: Calendar, color: 'border-purple-500 bg-purple-500/10', category: 'trigger' },
  trigger_webhook: { icon: Webhook, color: 'border-blue-500 bg-blue-500/10', category: 'trigger' },
  trigger_manual: { icon: MousePointerClick, color: 'border-green-500 bg-green-500/10', category: 'trigger' },
  http_request: { icon: Globe, color: 'border-cyan-500 bg-cyan-500/10', category: 'action' },
  connector_action: { icon: Play, color: 'border-pink-500 bg-pink-500/10', category: 'action' },
  condition: { icon: GitBranch, color: 'border-yellow-500 bg-yellow-500/10', category: 'logic' },
  transform: { icon: Settings, color: 'border-indigo-500 bg-indigo-500/10', category: 'logic' },
  delay: { icon: Clock, color: 'border-gray-500 bg-gray-500/10', category: 'utility' },
  loop: { icon: Repeat, color: 'border-teal-500 bg-teal-500/10', category: 'logic' },
  set_variable: { icon: Variable, color: 'border-violet-500 bg-violet-500/10', category: 'utility' },
}

export interface WorkflowNodeData {
  label: string
  node_type: WorkflowNodeType
  config?: Record<string, unknown>
  on_error?: string
}

function WorkflowNodeComponent({ data, selected }: NodeProps<WorkflowNodeData>) {
  const config = nodeTypeConfig[data.node_type] || {
    icon: Settings,
    color: 'border-gray-500 bg-gray-500/10',
    category: 'unknown',
  }
  const Icon = config.icon
  const isTrigger = config.category === 'trigger'
  const isCondition = data.node_type === 'condition'
  const isLoop = data.node_type === 'loop'

  return (
    <div
      className={cn(
        'px-4 py-3 rounded-lg border-2 min-w-[180px] transition-shadow',
        config.color,
        selected && 'ring-2 ring-primary ring-offset-2 ring-offset-background'
      )}
    >
      {/* Input Handle (not for triggers) */}
      {!isTrigger && (
        <Handle
          type="target"
          position={Position.Top}
          className="!w-3 !h-3 !bg-muted-foreground !border-2 !border-background"
        />
      )}

      {/* Node Content */}
      <div className="flex items-center gap-2">
        <Icon size={18} className="text-muted-foreground" />
        <div className="flex-1 min-w-0">
          <div className="font-medium text-sm truncate">{data.label}</div>
          <div className="text-xs text-muted-foreground capitalize">
            {data.node_type.replace(/_/g, ' ')}
          </div>
        </div>
      </div>

      {/* Output Handles */}
      {isCondition ? (
        // Condition node has true/false outputs
        <>
          <Handle
            type="source"
            position={Position.Bottom}
            id="true"
            className="!w-3 !h-3 !bg-green-500 !border-2 !border-background"
            style={{ left: '30%' }}
          />
          <Handle
            type="source"
            position={Position.Bottom}
            id="false"
            className="!w-3 !h-3 !bg-red-500 !border-2 !border-background"
            style={{ left: '70%' }}
          />
          <div className="flex justify-between text-[10px] text-muted-foreground mt-1 px-2">
            <span>true</span>
            <span>false</span>
          </div>
        </>
      ) : isLoop ? (
        // Loop node has loop_item and loop_complete outputs
        <>
          <Handle
            type="source"
            position={Position.Bottom}
            id="loop_item"
            className="!w-3 !h-3 !bg-teal-500 !border-2 !border-background"
            style={{ left: '30%' }}
          />
          <Handle
            type="source"
            position={Position.Bottom}
            id="loop_complete"
            className="!w-3 !h-3 !bg-muted-foreground !border-2 !border-background"
            style={{ left: '70%' }}
          />
          <div className="flex justify-between text-[10px] text-muted-foreground mt-1 px-2">
            <span>each</span>
            <span>done</span>
          </div>
        </>
      ) : (
        // Default single output
        <Handle
          type="source"
          position={Position.Bottom}
          id="default"
          className="!w-3 !h-3 !bg-muted-foreground !border-2 !border-background"
        />
      )}
    </div>
  )
}

export default memo(WorkflowNodeComponent)
