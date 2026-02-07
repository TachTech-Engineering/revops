/**
 * PipelineEditorPage - Visual pipeline builder using React Flow.
 *
 * Provides a drag-and-drop interface for building data pipelines
 * with transform, filter, and route stages.
 */

import { useCallback, useEffect, useState, DragEvent } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import ReactFlow, {
  Node,
  Edge,
  Controls,
  Background,
  BackgroundVariant,
  useNodesState,
  useEdgesState,
  addEdge,
  Connection,
  ReactFlowProvider,
  useReactFlow,
  Panel,
} from 'reactflow'
import 'reactflow/dist/style.css'
import {
  Save,
  Play,
  ArrowLeft,
  Settings,
  ZoomIn,
  ZoomOut,
  Maximize,
} from 'lucide-react'
import { cn, generateNodeId, generateEdgeId } from '../lib/utils'
import {
  useGetPipelineQuery,
  useCreatePipelineMutation,
  useUpdatePipelineMutation,
  useExecutePipelineMutation,
  PipelineStage,
  PipelineEdge,
  StageCategory,
} from '../api/pantherApi'
import StagePalette from '../components/pipeline/StagePalette'
import StagePropertiesPanel from '../components/pipeline/StagePropertiesPanel'
import { StageNodeData, stageNodeTypes } from '../components/pipeline/StageNode'

interface PipelineEditorContentProps {
  pipelineId?: string
}

function PipelineEditorContent({ pipelineId }: PipelineEditorContentProps) {
  const navigate = useNavigate()
  const reactFlowInstance = useReactFlow()

  // API hooks
  const { data: pipeline, isLoading: isLoadingPipeline } = useGetPipelineQuery(pipelineId ?? '', {
    skip: !pipelineId,
  })
  const [createPipeline, { isLoading: isCreating }] = useCreatePipelineMutation()
  const [updatePipeline, { isLoading: isUpdating }] = useUpdatePipelineMutation()
  const [executePipeline, { isLoading: isExecuting }] = useExecutePipelineMutation()

  // React Flow state
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const [selectedNode, setSelectedNode] = useState<Node<StageNodeData> | null>(null)

  // Pipeline metadata
  const [pipelineName, setPipelineName] = useState('')
  const [pipelineDescription, setPipelineDescription] = useState('')
  const [showSettings, setShowSettings] = useState(false)

  // Convert PipelineStage to React Flow node
  const stageToNode = useCallback((stage: PipelineStage): Node<StageNodeData> => ({
    id: stage.node_key,
    type: 'stageNode',
    position: { x: stage.position_x, y: stage.position_y },
    data: {
      label: stage.label || stage.stage_type,
      stageType: stage.stage_type,
      category: getCategoryForStageType(stage.stage_type),
      config: stage.config,
      enabled: stage.enabled,
    },
  }), [])

  // Convert PipelineEdge to React Flow edge
  const pipelineEdgeToReactFlow = useCallback((edge: PipelineEdge): Edge => ({
    id: edge.id,
    source: edge.source_node_key,
    sourceHandle: edge.source_handle,
    target: edge.target_node_key,
    targetHandle: edge.target_handle,
    label: edge.label,
    animated: true,
    style: { stroke: '#6366f1' },
  }), [])

  // Get category for a stage type
  function getCategoryForStageType(stageType: string): StageCategory {
    const transformTypes = ['ocsf_transform', 'field_mapper', 'parse_json']
    const filterTypes = ['condition_filter', 'sample', 'dedupe']
    if (transformTypes.includes(stageType)) return 'transform'
    if (filterTypes.includes(stageType)) return 'filter'
    return 'route'
  }

  // Load pipeline data
  useEffect(() => {
    if (pipeline) {
      setPipelineName(pipeline.name)
      setPipelineDescription(pipeline.description || '')
      setNodes(pipeline.stages.map(stageToNode))
      setEdges(pipeline.edges.map(pipelineEdgeToReactFlow))

      // Restore viewport if available
      if (pipeline.viewport) {
        reactFlowInstance.setViewport(pipeline.viewport)
      }
    } else if (!pipelineId) {
      // New pipeline defaults
      setPipelineName('New Pipeline')
      setPipelineDescription('')
      setNodes([])
      setEdges([])
    }
  }, [pipeline, pipelineId, stageToNode, pipelineEdgeToReactFlow, reactFlowInstance])

  // Handle connections
  const onConnect = useCallback(
    (connection: Connection) => {
      setEdges((eds) =>
        addEdge(
          {
            ...connection,
            id: generateEdgeId(connection.source!, connection.target!),
            animated: true,
            style: { stroke: '#6366f1' },
          },
          eds
        )
      )
    },
    [setEdges]
  )

  // Handle node selection
  const onNodeClick = useCallback((_: React.MouseEvent, node: Node<StageNodeData>) => {
    setSelectedNode(node)
  }, [])

  // Handle canvas click (deselect)
  const onPaneClick = useCallback(() => {
    setSelectedNode(null)
  }, [])

  // Handle drag over
  const onDragOver = useCallback((event: DragEvent) => {
    event.preventDefault()
    event.dataTransfer.dropEffect = 'move'
  }, [])

  // Handle drop
  const onDrop = useCallback(
    (event: DragEvent) => {
      event.preventDefault()

      const data = event.dataTransfer.getData('application/reactflow')
      if (!data) return

      const stageData = JSON.parse(data)
      const position = reactFlowInstance.screenToFlowPosition({
        x: event.clientX,
        y: event.clientY,
      })

      const newNode: Node<StageNodeData> = {
        id: generateNodeId(),
        type: 'stageNode',
        position,
        data: {
          label: stageData.label,
          stageType: stageData.stageType,
          category: stageData.category,
          config: stageData.config || {},
          enabled: true,
        },
      }

      setNodes((nds) => [...nds, newNode])
    },
    [reactFlowInstance, setNodes]
  )

  // Handle node config update
  const handleNodeUpdate = useCallback(
    (nodeId: string, config: Record<string, unknown>) => {
      setNodes((nds) =>
        nds.map((node) => {
          if (node.id === nodeId) {
            return {
              ...node,
              data: {
                ...node.data,
                config,
              },
            }
          }
          return node
        })
      )
    },
    [setNodes]
  )

  // Handle node delete
  const handleNodeDelete = useCallback(
    (nodeId: string) => {
      setNodes((nds) => nds.filter((node) => node.id !== nodeId))
      setEdges((eds) =>
        eds.filter((edge) => edge.source !== nodeId && edge.target !== nodeId)
      )
      setSelectedNode(null)
    },
    [setNodes, setEdges]
  )

  // Save pipeline
  const handleSave = async () => {
    const viewport = reactFlowInstance.getViewport()

    const stagesData = nodes.map((node) => ({
      node_key: node.id,
      stage_type: node.data.stageType,
      label: node.data.label,
      position_x: node.position.x,
      position_y: node.position.y,
      config: node.data.config,
      enabled: node.data.enabled,
    }))

    const edgesData = edges.map((edge) => ({
      source_node_key: edge.source,
      source_handle: edge.sourceHandle || 'default',
      target_node_key: edge.target,
      target_handle: edge.targetHandle || 'default',
      condition: undefined,
      label: edge.label as string | undefined,
    }))

    try {
      if (pipelineId) {
        await updatePipeline({
          id: pipelineId,
          update: {
            name: pipelineName,
            description: pipelineDescription,
            stages: stagesData,
            edges: edgesData,
            viewport,
          },
        }).unwrap()
        alert('Pipeline saved successfully!')
      } else {
        const result = await createPipeline({
          name: pipelineName,
          description: pipelineDescription,
          stages: stagesData,
          edges: edgesData,
          viewport,
        }).unwrap()
        navigate(`/pipelines/${result.id}`, { replace: true })
        alert('Pipeline created successfully!')
      }
    } catch (err) {
      alert('Failed to save pipeline')
    }
  }

  // Execute pipeline
  const handleExecute = async () => {
    if (!pipelineId) {
      alert('Please save the pipeline first')
      return
    }

    try {
      const result = await executePipeline({ id: pipelineId }).unwrap()
      alert(
        `Pipeline executed: ${result.events_output} events processed, ` +
        `${result.events_filtered} filtered (${result.duration_ms}ms)`
      )
    } catch (err) {
      alert('Failed to execute pipeline')
    }
  }

  const isSaving = isCreating || isUpdating

  return (
    <div className="h-screen flex flex-col bg-background">
      {/* Header */}
      <header className="h-14 border-b flex items-center justify-between px-4 shrink-0">
        <div className="flex items-center gap-4">
          <Link
            to="/pipelines"
            className="p-2 rounded hover:bg-accent text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft size={20} />
          </Link>

          <input
            type="text"
            value={pipelineName}
            onChange={(e) => setPipelineName(e.target.value)}
            className="text-lg font-semibold bg-transparent border-none focus:outline-none focus:ring-2 focus:ring-primary rounded px-2 py-1"
            placeholder="Pipeline name"
          />
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowSettings(!showSettings)}
            className={cn(
              'p-2 rounded hover:bg-accent text-muted-foreground hover:text-foreground',
              showSettings && 'bg-accent text-foreground'
            )}
            title="Pipeline Settings"
          >
            <Settings size={20} />
          </button>

          <div className="w-px h-6 bg-border mx-2" />

          <button
            onClick={handleExecute}
            disabled={isExecuting || !pipelineId}
            className="flex items-center gap-2 px-3 py-1.5 rounded-md border hover:bg-accent disabled:opacity-50 text-sm"
            title={!pipelineId ? 'Save pipeline first to execute' : 'Execute Pipeline'}
          >
            <Play size={16} className={isExecuting ? 'animate-pulse' : ''} />
            Test
          </button>

          <button
            onClick={handleSave}
            disabled={isSaving}
            className="flex items-center gap-2 px-4 py-1.5 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 text-sm font-medium"
          >
            <Save size={16} className={isSaving ? 'animate-pulse' : ''} />
            {pipelineId ? 'Save' : 'Create'}
          </button>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Stage Palette */}
        <StagePalette />

        {/* React Flow Canvas */}
        <div className="flex-1 relative">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onNodeClick={onNodeClick}
            onPaneClick={onPaneClick}
            onDragOver={onDragOver}
            onDrop={onDrop}
            nodeTypes={stageNodeTypes}
            fitView
            snapToGrid
            snapGrid={[16, 16]}
            defaultEdgeOptions={{
              animated: true,
              style: { stroke: '#6366f1' },
            }}
          >
            <Background variant={BackgroundVariant.Dots} gap={16} size={1} />
            <Controls
              position="bottom-left"
              showInteractive={false}
            />

            {/* Empty state */}
            {nodes.length === 0 && (
              <Panel position="top-center" className="mt-20">
                <div className="bg-background/80 backdrop-blur-sm rounded-lg border p-6 text-center max-w-sm">
                  <h3 className="font-semibold mb-2">Get Started</h3>
                  <p className="text-sm text-muted-foreground">
                    Drag stages from the left panel onto the canvas to build your pipeline.
                    Connect stages by dragging from output handles to input handles.
                  </p>
                </div>
              </Panel>
            )}
          </ReactFlow>

          {/* Quick actions */}
          <div className="absolute bottom-4 right-4 flex items-center gap-2 bg-background rounded-lg border p-1">
            <button
              onClick={() => reactFlowInstance.zoomIn()}
              className="p-2 rounded hover:bg-accent"
              title="Zoom In"
            >
              <ZoomIn size={16} />
            </button>
            <button
              onClick={() => reactFlowInstance.zoomOut()}
              className="p-2 rounded hover:bg-accent"
              title="Zoom Out"
            >
              <ZoomOut size={16} />
            </button>
            <button
              onClick={() => reactFlowInstance.fitView()}
              className="p-2 rounded hover:bg-accent"
              title="Fit View"
            >
              <Maximize size={16} />
            </button>
          </div>
        </div>

        {/* Properties Panel */}
        <StagePropertiesPanel
          selectedNode={selectedNode}
          onUpdate={handleNodeUpdate}
          onDelete={handleNodeDelete}
          onClose={() => setSelectedNode(null)}
        />
      </div>

      {/* Settings Modal */}
      {showSettings && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-background rounded-lg border shadow-lg w-full max-w-md">
            <div className="p-4 border-b flex items-center justify-between">
              <h2 className="font-semibold">Pipeline Settings</h2>
              <button
                onClick={() => setShowSettings(false)}
                className="p-1 rounded hover:bg-accent"
              >
                <ArrowLeft size={18} />
              </button>
            </div>
            <div className="p-4 space-y-4">
              <div>
                <label className="text-sm font-medium">Name</label>
                <input
                  type="text"
                  value={pipelineName}
                  onChange={(e) => setPipelineName(e.target.value)}
                  className="w-full mt-1 px-3 py-2 rounded-md border bg-background"
                />
              </div>
              <div>
                <label className="text-sm font-medium">Description</label>
                <textarea
                  value={pipelineDescription}
                  onChange={(e) => setPipelineDescription(e.target.value)}
                  rows={3}
                  className="w-full mt-1 px-3 py-2 rounded-md border bg-background resize-none"
                  placeholder="Describe what this pipeline does..."
                />
              </div>
            </div>
            <div className="p-4 border-t flex justify-end gap-2">
              <button
                onClick={() => setShowSettings(false)}
                className="px-4 py-2 rounded-md border hover:bg-accent text-sm"
              >
                Cancel
              </button>
              <button
                onClick={() => setShowSettings(false)}
                className="px-4 py-2 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 text-sm font-medium"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// Wrapper with ReactFlowProvider
export default function PipelineEditorPage() {
  const { pipelineId } = useParams()

  return (
    <ReactFlowProvider>
      <PipelineEditorContent pipelineId={pipelineId} />
    </ReactFlowProvider>
  )
}
