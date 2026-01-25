import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  useGetDashboardQuery,
  useUpdateDashboardMutation,
  useGetWidgetTypesQuery,
  type WidgetConfig,
  type LayoutItem,
  type WidgetType,
} from '../api/pantherApi'
import { WidgetRenderer, widgetTypeLabels } from '../components/dashboard/widgets'

export default function CustomDashboardPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [isEditing, setIsEditing] = useState(false)
  const [showAddWidget, setShowAddWidget] = useState(false)

  const { data: dashboard, isLoading, error } = useGetDashboardQuery(id!)
  const { data: widgetTypes } = useGetWidgetTypesQuery()
  const [updateDashboard] = useUpdateDashboardMutation()

  const [localLayout, setLocalLayout] = useState<LayoutItem[]>([])
  const [localWidgets, setLocalWidgets] = useState<WidgetConfig[]>([])

  useEffect(() => {
    if (dashboard) {
      setLocalLayout(dashboard.layout)
      setLocalWidgets(dashboard.widgets)
    }
  }, [dashboard])

  const handleSave = async () => {
    try {
      await updateDashboard({
        id: id!,
        update: { layout: localLayout, widgets: localWidgets },
      }).unwrap()
      setIsEditing(false)
    } catch (err) {
      console.error('Failed to save dashboard:', err)
    }
  }

  const handleAddWidget = (widgetType: WidgetType) => {
    const newWidgetId = `widget-${Date.now()}`
    const typeInfo = widgetTypes?.find(t => t.value === widgetType)

    const newWidget: WidgetConfig = {
      id: newWidgetId,
      widget_type: widgetType,
      title: widgetTypeLabels[widgetType] || widgetType,
      config: {},
    }

    const newLayoutItem: LayoutItem = {
      i: newWidgetId,
      x: 0,
      y: Math.max(0, ...localLayout.map(l => l.y + l.h)),
      w: typeInfo?.default_size.w || 3,
      h: typeInfo?.default_size.h || 3,
    }

    setLocalWidgets([...localWidgets, newWidget])
    setLocalLayout([...localLayout, newLayoutItem])
    setShowAddWidget(false)
  }

  const handleRemoveWidget = (widgetId: string) => {
    setLocalWidgets(localWidgets.filter(w => w.id !== widgetId))
    setLocalLayout(localLayout.filter(l => l.i !== widgetId))
  }

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  if (error || !dashboard) {
    return (
      <div className="p-6">
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-red-700">
          Failed to load dashboard
        </div>
      </div>
    )
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">{dashboard.name}</h1>
          {dashboard.description && (
            <p className="text-gray-600 mt-1">{dashboard.description}</p>
          )}
        </div>
        <div className="flex gap-2">
          {isEditing ? (
            <>
              <button
                onClick={() => setShowAddWidget(true)}
                className="px-4 py-2 border border-blue-300 text-blue-700 rounded-lg hover:bg-blue-50"
              >
                Add Widget
              </button>
              <button
                onClick={() => {
                  setLocalLayout(dashboard.layout)
                  setLocalWidgets(dashboard.widgets)
                  setIsEditing(false)
                }}
                className="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                Save
              </button>
            </>
          ) : (
            <button
              onClick={() => setIsEditing(true)}
              className="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50"
            >
              Edit Dashboard
            </button>
          )}
        </div>
      </div>

      {/* Widget Grid */}
      <div className="grid grid-cols-12 gap-4 auto-rows-[100px]">
        {localWidgets.map((widget) => {
          const layout = localLayout.find(l => l.i === widget.id)
          if (!layout) return null

          return (
            <div
              key={widget.id}
              className="bg-white rounded-lg shadow relative"
              style={{
                gridColumn: `span ${layout.w}`,
                gridRow: `span ${layout.h}`,
              }}
            >
              {/* Widget Header */}
              <div className="flex justify-between items-center px-4 py-2 border-b bg-gray-50 rounded-t-lg">
                <h3 className="font-medium text-gray-900 text-sm">{widget.title}</h3>
                {isEditing && (
                  <button
                    onClick={() => handleRemoveWidget(widget.id)}
                    className="text-red-500 hover:text-red-700"
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </button>
                )}
              </div>

              {/* Widget Content */}
              <div className="h-[calc(100%-40px)] overflow-hidden">
                <WidgetRenderer widget={widget} />
              </div>
            </div>
          )
        })}

        {localWidgets.length === 0 && (
          <div className="col-span-12 row-span-3 flex items-center justify-center bg-gray-50 rounded-lg border-2 border-dashed border-gray-300">
            <div className="text-center">
              <div className="text-gray-400 text-4xl mb-2">📊</div>
              <p className="text-gray-500">No widgets yet</p>
              {isEditing && (
                <button
                  onClick={() => setShowAddWidget(true)}
                  className="mt-2 text-blue-600 hover:text-blue-800"
                >
                  Add your first widget
                </button>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Add Widget Modal */}
      {showAddWidget && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl mx-4 max-h-[80vh] overflow-y-auto">
            <div className="flex justify-between items-center px-6 py-4 border-b sticky top-0 bg-white">
              <h2 className="text-lg font-semibold">Add Widget</h2>
              <button
                onClick={() => setShowAddWidget(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div className="p-6 grid grid-cols-2 gap-4">
              {widgetTypes?.map((type) => (
                <button
                  key={type.value}
                  onClick={() => handleAddWidget(type.value)}
                  className="p-4 border border-gray-200 rounded-lg hover:border-blue-500 hover:bg-blue-50 text-left transition-colors"
                >
                  <h3 className="font-medium text-gray-900">{type.label}</h3>
                  <p className="text-sm text-gray-500 mt-1">{type.description}</p>
                  <p className="text-xs text-gray-400 mt-2">
                    Size: {type.default_size.w} x {type.default_size.h}
                  </p>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
