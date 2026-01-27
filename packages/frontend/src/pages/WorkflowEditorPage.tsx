import { useState, useCallback, useEffect, useRef, DragEvent } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import ReactFlow, {
  Node,
  Edge,
  Controls,
  Background,
  MiniMap,
  useNodesState,
  useEdgesState,
  addEdge,
  Connection,
  ReactFlowProvider,
  ReactFlowInstance,
} from 'reactflow'
import 'reactflow/dist/style.css'
import { ArrowLeft, Save, Play, Settings } from 'lucide-react'
import {
  useGetWorkflowQuery,
  useCreateWorkflowMutation,
  useUpdateWorkflowMutation,
  useExecuteWorkflowMutation,
  WorkflowStatus,
  WorkflowNodeType,
  WorkflowNodeCreate,
  WorkflowEdgeCreate,
} from '../api/pantherApi'
import { cn } from '../lib/utils'
import WorkflowNodeComponent, { WorkflowNodeData } from '../components/workflow/WorkflowNode'
import NodePalette from '../components/workflow/NodePalette'
import NodePropertiesPanel from '../components/workflow/NodePropertiesPanel'

const nodeTypes = {
  workflowNode: WorkflowNodeComponent,
}

let nodeId = 0
const getNodeId = () => `node_${nodeId++}`

interface WorkflowFormData {
  name: string
  description: string
  status: WorkflowStatus
}

function WorkflowEditorContent() {
  const navigate = useNavigate()
  const { workflowId } = useParams()
  const isEditing = !!workflowId && workflowId !== 'new'
  const reactFlowWrapper = useRef<HTMLDivElement>(null)
  const [reactFlowInstance, setReactFlowInstance] = useState<ReactFlowInstance | null>(null)

  const { data: existingWorkflow, isLoading: isLoadingWorkflow } = useGetWorkflowQuery(workflowId!, {
    skip: !isEditing,
  })

  const [createWorkflow, { isLoading: isCreating }] = useCreateWorkflowMutation()
  const [updateWorkflow, { isLoading: isUpdating }] = useUpdateWorkflowMutation()
  const [executeWorkflow] = useExecuteWorkflowMutation()

  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const [selectedNode, setSelectedNode] = useState<Node<WorkflowNodeData> | null>(null)
  const [showSettings, setShowSettings] = useState(false)

  const [formData, setFormData] = useState<WorkflowFormData>({
    name: '',
    description: '',
    status: 'draft',
  })

  // Load existing workflow
  useEffect(() => {
    if (existingWorkflow) {
      setFormData({
        name: existingWorkflow.name,
        description: existingWorkflow.description || '',
        status: existingWorkflow.status,
      })

      // Convert backend nodes to React Flow nodes
      const flowNodes: Node<WorkflowNodeData>[] = existingWorkflow.nodes.map((n) => ({
        id: n.node_key,
        type: 'workflowNode',
        position: { x: n.position_x, y: n.position_y },
        data: {
          label: n.label,
          node_type: n.node_type,
          config: n.config,
          on_error: n.on_error,
        },
      }))

      // Convert backend edges to React Flow edges
      const flowEdges: Edge[] = existingWorkflow.edges.map((e) => ({
        id: `${e.source_node_key}-${e.source_handle}-${e.target_node_key}`,
        source: e.source_node_key,
        sourceHandle: e.source_handle,
        target: e.target_node_key,
      }))

      setNodes(flowNodes)
      setEdges(flowEdges)

      // Update node ID counter
      const maxId = existingWorkflow.nodes.reduce((max, n) => {
        const match = n.node_key.match(/node_(\d+)/)
        return match ? Math.max(max, parseInt(match[1])) : max
      }, 0)
      nodeId = maxId + 1

      // Set viewport
      if (reactFlowInstance && existingWorkflow.viewport) {
        reactFlowInstance.setViewport(existingWorkflow.viewport)
      }
    }
  }, [existingWorkflow, reactFlowInstance, setNodes, setEdges])

  const onConnect = useCallback(
    (params: Connection) => setEdges((eds) => addEdge(params, eds)),
    [setEdges]
  )

  const onDragOver = useCallback((event: DragEvent) => {
    event.preventDefault()
    event.dataTransfer.dropEffect = 'move'
  }, [])

  const onDrop = useCallback(
    (event: DragEvent) => {
      event.preventDefault()

      const type = event.dataTransfer.getData('application/reactflow') as WorkflowNodeType
      if (!type || !reactFlowInstance || !reactFlowWrapper.current) return

      const reactFlowBounds = reactFlowWrapper.current.getBoundingClientRect()
      const position = reactFlowInstance.project({
        x: event.clientX - reactFlowBounds.left,
        y: event.clientY - reactFlowBounds.top,
      })

      const newNode: Node<WorkflowNodeData> = {
        id: getNodeId(),
        type: 'workflowNode',
        position,
        data: {
          label: type.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()),
          node_type: type,
          config: {},
        },
      }

      setNodes((nds) => nds.concat(newNode))
    },
    [reactFlowInstance, setNodes]
  )

  const onNodeClick = useCallback((_: React.MouseEvent, node: Node<WorkflowNodeData>) => {
    setSelectedNode(node)
  }, [])

  const handleNodeUpdate = useCallback(
    (nodeId: string, data: Partial<WorkflowNodeData>) => {
      setNodes((nds) =>
        nds.map((node) =>
          node.id === nodeId ? { ...node, data: { ...node.data, ...data } } : node
        )
      )
      if (selectedNode?.id === nodeId) {
        setSelectedNode((prev) => (prev ? { ...prev, data: { ...prev.data, ...data } } : null))
      }
    },
    [setNodes, selectedNode]
  )

  const handleSave = async () => {
    if (!formData.name.trim()) {
      alert('Please enter a workflow name')
      return
    }

    // Find trigger node
    const triggerNode = nodes.find((n) =>
      ['trigger_alert', 'trigger_schedule', 'trigger_webhook', 'trigger_manual'].includes(
        n.data.node_type
      )
    )

    // Convert nodes to backend format
    const workflowNodes: WorkflowNodeCreate[] = nodes.map((n) => ({
      node_key: n.id,
      node_type: n.data.node_type,
      label: n.data.label,
      position_x: n.position.x,
      position_y: n.position.y,
      config: n.data.config,
      on_error: n.data.on_error,
    }))

    // Convert edges to backend format
    const workflowEdges: WorkflowEdgeCreate[] = edges.map((e) => ({
      source_node_key: e.source,
      source_handle: e.sourceHandle || 'default',
      target_node_key: e.target,
    }))

    // Get viewport
    const viewport = reactFlowInstance?.getViewport()

    try {
      if (isEditing) {
        await updateWorkflow({
          id: workflowId!,
          update: {
            name: formData.name,
            description: formData.description || undefined,
            status: formData.status,
            trigger_type: triggerNode?.data.node_type,
            trigger_config: triggerNode?.data.config,
            nodes: workflowNodes,
            edges: workflowEdges,
            viewport: viewport || { x: 0, y: 0, zoom: 1 },
          },
        }).unwrap()
      } else {
        await createWorkflow({
          name: formData.name,
          description: formData.description || undefined,
          status: formData.status,
          trigger_type: triggerNode?.data.node_type,
          trigger_config: triggerNode?.data.config,
          nodes: workflowNodes,
          edges: workflowEdges,
          viewport: viewport || { x: 0, y: 0, zoom: 1 },
        }).unwrap()
      }
      navigate('/workflows')
    } catch (err) {
      console.error('Failed to save workflow:', err)
      alert('Failed to save workflow')
    }
  }

  const handleExecute = async () => {
    if (!isEditing) return
    try {
      const result = await executeWorkflow({ workflowId: workflowId! }).unwrap()
      alert(`Workflow execution started: ${result.id}`)
    } catch (err) {
      alert('Failed to execute workflow')
    }
  }

  if (isEditing && isLoadingWorkflow) {
    return <div className="p-6 text-center text-muted-foreground">Loading workflow...</div>
  }

  return (
    <div className="h-[calc(100vh-64px)] flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b bg-background">
        <div className="flex items-center gap-4">
          <button onClick={() => navigate('/workflows')} className="p-2 hover:bg-accent rounded-md">
            <ArrowLeft size={20} />
          </button>
          <div>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData((prev) => ({ ...prev, name: e.target.value }))}
              placeholder="Workflow Name"
              className="text-xl font-bold bg-transparent border-none outline-none"
            />
          </div>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={formData.status}
            onChange={(e) =>
              setFormData((prev) => ({ ...prev, status: e.target.value as WorkflowStatus }))
            }
            className="px-3 py-2 rounded-md border bg-background text-sm"
          >
            <option value="draft">Draft</option>
            <option value="active">Active</option>
            <option value="inactive">Inactive</option>
          </select>
          <button
            onClick={() => setShowSettings(!showSettings)}
            className={cn(
              'p-2 rounded-md',
              showSettings ? 'bg-accent' : 'hover:bg-accent'
            )}
          >
            <Settings size={18} />
          </button>
          {isEditing && formData.status === 'active' && (
            <button
              onClick={handleExecute}
              className="flex items-center gap-2 px-4 py-2 bg-muted text-muted-foreground rounded-md font-medium hover:bg-accent"
            >
              <Play size={18} />
              Run
            </button>
          )}
          <button
            onClick={handleSave}
            disabled={isCreating || isUpdating}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md font-medium hover:bg-primary/90 disabled:opacity-50"
          >
            <Save size={18} />
            {isCreating || isUpdating ? 'Saving...' : 'Save'}
          </button>
        </div>
      </div>

      {/* Settings Panel (collapsible) */}
      {showSettings && (
        <div className="p-4 border-b bg-muted/50">
          <div className="max-w-2xl space-y-4">
            <div>
              <label className="block text-sm font-medium mb-1">Description</label>
              <textarea
                value={formData.description}
                onChange={(e) => setFormData((prev) => ({ ...prev, description: e.target.value }))}
                className="w-full px-3 py-2 rounded-md border bg-background text-sm"
                rows={2}
                placeholder="Describe what this workflow does"
              />
            </div>
          </div>
        </div>
      )}

      {/* Main Content */}
      <div className="flex-1 flex">
        {/* Node Palette */}
        <NodePalette />

        {/* Canvas */}
        <div ref={reactFlowWrapper} className="flex-1">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onInit={setReactFlowInstance}
            onDrop={onDrop}
            onDragOver={onDragOver}
            onNodeClick={onNodeClick}
            nodeTypes={nodeTypes}
            fitView
            deleteKeyCode={['Backspace', 'Delete']}
            className="bg-muted/30"
          >
            <Controls />
            <MiniMap
              nodeColor={(node) => {
                const type = (node.data as WorkflowNodeData).node_type
                if (type.startsWith('trigger')) return '#f97316'
                if (type === 'http_request' || type === 'connector_action') return '#06b6d4'
                if (type === 'condition' || type === 'loop' || type === 'transform') return '#eab308'
                return '#6b7280'
              }}
              className="!bg-background"
            />
            <Background gap={20} size={1} />
          </ReactFlow>
        </div>

        {/* Properties Panel */}
        {selectedNode && (
          <NodePropertiesPanel
            node={selectedNode}
            onClose={() => setSelectedNode(null)}
            onUpdate={handleNodeUpdate}
          />
        )}
      </div>
    </div>
  )
}

export default function WorkflowEditorPage() {
  return (
    <ReactFlowProvider>
      <WorkflowEditorContent />
    </ReactFlowProvider>
  )
}
