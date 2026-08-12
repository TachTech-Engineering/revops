import { useState } from 'react'
import {
  Calendar,
  Plus,
  Trash2,
  Users,
  Clock,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  UserCheck,
  UserX,
} from 'lucide-react'
import {
  useListOnCallSchedulesQuery,
  useCreateOnCallScheduleMutation,
  useDeleteOnCallScheduleMutation,
  useGetCurrentOnCallQuery,
  useCreateOnCallOverrideMutation,
  useGetOnCallCalendarQuery,
  OnCallScheduleCreate,
  OnCallMemberCreate,
} from '../api/pantherApi'
import { cn } from '../lib/utils'

export default function OnCallSchedulesPage() {
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showOverrideModal, setShowOverrideModal] = useState(false)
  const [selectedScheduleId, setSelectedScheduleId] = useState<string | null>(null)
  const [calendarMonth, setCalendarMonth] = useState(new Date())

  const { data: schedules, isLoading } = useListOnCallSchedulesQuery({})
  const { data: currentOnCall } = useGetCurrentOnCallQuery()
  const [createSchedule, { isLoading: isCreating }] = useCreateOnCallScheduleMutation()
  const [deleteSchedule] = useDeleteOnCallScheduleMutation()
  const [createOverride] = useCreateOnCallOverrideMutation()

  // Calendar query
  const startDate = new Date(calendarMonth.getFullYear(), calendarMonth.getMonth(), 1)
  const endDate = new Date(calendarMonth.getFullYear(), calendarMonth.getMonth() + 1, 0)
  const { data: calendarEvents } = useGetOnCallCalendarQuery({
    startDate: startDate.toISOString().split('T')[0],
    endDate: endDate.toISOString().split('T')[0],
    scheduleId: selectedScheduleId || undefined,
  })

  const [newSchedule, setNewSchedule] = useState<OnCallScheduleCreate & { members: OnCallMemberCreate[] }>({
    name: '',
    description: '',
    timezone: 'UTC',
    rotation_type: 'weekly',
    handoff_time: '09:00',
    handoff_day: 0,
    is_active: true,
    members: [],
  })

  const [newMember, setNewMember] = useState({
    user_email: '',
    user_name: '',
    rotation_order: 1,
    role: 'primary',
  })

  const [override, setOverride] = useState({
    schedule_id: '',
    override_user_email: '',
    start_time: '',
    end_time: '',
    reason: '',
  })

  const handleCreate = async () => {
    try {
      await createSchedule(newSchedule).unwrap()
      setShowCreateModal(false)
      setNewSchedule({
        name: '',
        description: '',
        timezone: 'UTC',
        rotation_type: 'weekly',
        handoff_time: '09:00',
        handoff_day: 0,
        is_active: true,
        members: [],
      })
    } catch (err) {
      console.error('Failed to create schedule:', err)
    }
  }

  const handleDelete = async (scheduleId: string) => {
    if (!confirm('Are you sure you want to delete this schedule?')) return
    try {
      await deleteSchedule(scheduleId).unwrap()
    } catch (err) {
      console.error('Failed to delete schedule:', err)
    }
  }

  const handleCreateOverride = async () => {
    try {
      await createOverride({
        schedule_id: override.schedule_id,
        override_user_email: override.override_user_email,
        start_time: new Date(override.start_time).toISOString(),
        end_time: new Date(override.end_time).toISOString(),
        reason: override.reason,
      }).unwrap()
      setShowOverrideModal(false)
      setOverride({
        schedule_id: '',
        override_user_email: '',
        start_time: '',
        end_time: '',
        reason: '',
      })
    } catch (err) {
      console.error('Failed to create override:', err)
    }
  }

  const addMember = () => {
    setNewSchedule((prev) => ({
      ...prev,
      members: [
        ...prev.members,
        {
          ...newMember,
          rotation_order: prev.members.length + 1,
        },
      ],
    }))
    setNewMember({
      user_email: '',
      user_name: '',
      rotation_order: 1,
      role: 'primary',
    })
  }

  // Calendar helpers
  const getDaysInMonth = () => {
    const days = []
    const firstDay = new Date(calendarMonth.getFullYear(), calendarMonth.getMonth(), 1)
    const lastDay = new Date(calendarMonth.getFullYear(), calendarMonth.getMonth() + 1, 0)

    // Add padding for first week
    for (let i = 0; i < firstDay.getDay(); i++) {
      days.push(null)
    }

    for (let d = 1; d <= lastDay.getDate(); d++) {
      days.push(new Date(calendarMonth.getFullYear(), calendarMonth.getMonth(), d))
    }

    return days
  }

  const getEventForDate = (date: Date) => {
    if (!calendarEvents) return null
    const dateStr = date.toISOString().split('T')[0]
    return calendarEvents.find((e) => e.date === dateStr)
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Calendar className="text-primary" />
            On-Call Schedules
          </h1>
          <p className="text-muted-foreground mt-1">
            Manage rotation schedules and see who's on-call
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowOverrideModal(true)}
            className="flex items-center gap-2 px-4 py-2 border rounded-md hover:bg-accent"
          >
            <UserX size={16} />
            Create Override
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
          >
            <Plus size={16} />
            Create Schedule
          </button>
        </div>
      </div>

      {/* Current On-Call */}
      {currentOnCall && currentOnCall.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {currentOnCall.map((oc) => (
            <div
              key={oc.schedule_id}
              className={cn(
                'bg-card rounded-lg border p-4',
                oc.is_override && 'border-yellow-500/50'
              )}
            >
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-medium">{oc.schedule_name}</h3>
                {oc.is_override && (
                  <span className="px-2 py-0.5 bg-yellow-500/20 text-yellow-400 text-xs rounded">
                    Override Active
                  </span>
                )}
              </div>
              {oc.primary && (
                <div className="flex items-center gap-3 mb-2">
                  <div className="w-10 h-10 rounded-full bg-green-500/20 flex items-center justify-center">
                    <UserCheck className="text-green-400" size={20} />
                  </div>
                  <div>
                    <p className="font-medium">{oc.primary.user_name || oc.primary.user_email}</p>
                    <p className="text-xs text-muted-foreground">Primary On-Call</p>
                  </div>
                </div>
              )}
              {oc.backup && (
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-full bg-blue-500/20 flex items-center justify-center">
                    <Users className="text-blue-400" size={20} />
                  </div>
                  <div>
                    <p className="font-medium">{oc.backup.user_name || oc.backup.user_email}</p>
                    <p className="text-xs text-muted-foreground">Backup</p>
                  </div>
                </div>
              )}
              {oc.is_override && oc.override_end && (
                <p className="text-xs text-muted-foreground mt-3">
                  Override ends: {new Date(oc.override_end).toLocaleString()}
                </p>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Calendar View */}
      <div className="bg-card rounded-lg border p-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-medium flex items-center gap-2">
            <Calendar size={16} />
            On-Call Calendar
          </h3>
          <div className="flex items-center gap-2">
            <select
              value={selectedScheduleId || ''}
              onChange={(e) => setSelectedScheduleId(e.target.value || null)}
              className="px-3 py-1.5 bg-background border rounded-md text-sm"
            >
              <option value="">All Schedules</option>
              {schedules?.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </select>
            <button
              onClick={() =>
                setCalendarMonth(new Date(calendarMonth.getFullYear(), calendarMonth.getMonth() - 1))
              }
              className="p-1 hover:bg-accent rounded"
            >
              <ChevronLeft size={20} />
            </button>
            <span className="font-medium min-w-[140px] text-center">
              {calendarMonth.toLocaleDateString('en-US', { month: 'long', year: 'numeric' })}
            </span>
            <button
              onClick={() =>
                setCalendarMonth(new Date(calendarMonth.getFullYear(), calendarMonth.getMonth() + 1))
              }
              className="p-1 hover:bg-accent rounded"
            >
              <ChevronRight size={20} />
            </button>
          </div>
        </div>

        <div className="grid grid-cols-7 gap-1">
          {['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map((day) => (
            <div key={day} className="text-center text-xs text-muted-foreground py-2">
              {day}
            </div>
          ))}
          {getDaysInMonth().map((date, i) => {
            if (!date) {
              return <div key={`empty-${i}`} className="h-20" />
            }
            const event = getEventForDate(date)
            const isToday = date.toDateString() === new Date().toDateString()
            return (
              <div
                key={date.toISOString()}
                className={cn(
                  'h-20 border rounded p-1',
                  isToday && 'border-primary bg-primary/5'
                )}
              >
                <div className="text-xs font-medium">{date.getDate()}</div>
                {event && (
                  <div className="mt-1">
                    <div className="text-xs truncate text-green-400">
                      {event.primary_name || event.primary_email?.split('@')[0]}
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* Schedules List */}
      <div>
        <h3 className="font-medium mb-3">All Schedules</h3>
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <RefreshCw className="animate-spin text-muted-foreground" size={24} />
          </div>
        ) : !schedules?.length ? (
          <div className="text-center py-12 bg-card rounded-lg border">
            <Calendar className="mx-auto text-muted-foreground mb-4" size={48} />
            <h3 className="text-lg font-medium">No schedules configured</h3>
            <p className="text-muted-foreground mt-1">Create your first on-call schedule</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {schedules.map((schedule) => (
              <div key={schedule.id} className="bg-card rounded-lg border p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <div
                      className={cn(
                        'w-2 h-2 rounded-full',
                        schedule.is_active ? 'bg-green-500' : 'bg-gray-500'
                      )}
                    />
                    <h4 className="font-medium">{schedule.name}</h4>
                  </div>
                  <button
                    onClick={() => handleDelete(schedule.id)}
                    className="p-1 hover:bg-destructive/20 rounded text-destructive"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
                <div className="space-y-2 text-sm text-muted-foreground">
                  <div className="flex items-center gap-2">
                    <Clock size={14} />
                    <span>
                      {schedule.rotation_type} rotation at {schedule.handoff_time}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Users size={14} />
                    <span>{schedule.members?.length || 0} members</span>
                  </div>
                </div>
                {schedule.members && schedule.members.length > 0 && (
                  <div className="mt-3 pt-3 border-t">
                    <div className="flex flex-wrap gap-2">
                      {schedule.members.map((member, i) => (
                        <span
                          key={i}
                          className={cn(
                            'px-2 py-1 rounded text-xs',
                            member.role === 'primary'
                              ? 'bg-green-500/20 text-green-400'
                              : 'bg-blue-500/20 text-blue-400'
                          )}
                        >
                          {member.user_name || member.user_email}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Create Schedule Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
            <h2 className="text-lg font-semibold mb-4">Create On-Call Schedule</h2>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Schedule Name</label>
                <input
                  type="text"
                  value={newSchedule.name}
                  onChange={(e) => setNewSchedule({ ...newSchedule, name: e.target.value })}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                  placeholder="Primary On-Call"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-1">Rotation Type</label>
                  <select
                    value={newSchedule.rotation_type}
                    onChange={(e) =>
                      setNewSchedule({ ...newSchedule, rotation_type: e.target.value })
                    }
                    className="w-full px-3 py-2 bg-background border rounded-md"
                  >
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="custom">Custom</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Handoff Time</label>
                  <input
                    type="time"
                    value={newSchedule.handoff_time}
                    onChange={(e) =>
                      setNewSchedule({ ...newSchedule, handoff_time: e.target.value })
                    }
                    className="w-full px-3 py-2 bg-background border rounded-md"
                  />
                </div>
              </div>

              {/* Members */}
              <div>
                <label className="block text-sm font-medium mb-2">Rotation Members</label>
                {newSchedule.members.length > 0 && (
                  <div className="space-y-2 mb-3">
                    {newSchedule.members.map((member, index) => (
                      <div
                        key={index}
                        className="flex items-center justify-between p-2 bg-accent rounded"
                      >
                        <span className="text-sm">
                          #{index + 1} {member.user_email} ({member.role})
                        </span>
                        <button
                          onClick={() =>
                            setNewSchedule({
                              ...newSchedule,
                              members: newSchedule.members.filter((_, i) => i !== index),
                            })
                          }
                          className="text-destructive hover:text-destructive/80"
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    ))}
                  </div>
                )}

                <div className="grid grid-cols-1 md:grid-cols-4 gap-2">
                  <input
                    type="email"
                    value={newMember.user_email}
                    onChange={(e) => setNewMember({ ...newMember, user_email: e.target.value })}
                    placeholder="Email"
                    className="px-3 py-2 bg-background border rounded-md"
                  />
                  <input
                    type="text"
                    value={newMember.user_name}
                    onChange={(e) => setNewMember({ ...newMember, user_name: e.target.value })}
                    placeholder="Name"
                    className="px-3 py-2 bg-background border rounded-md"
                  />
                  <select
                    value={newMember.role}
                    onChange={(e) => setNewMember({ ...newMember, role: e.target.value })}
                    className="px-3 py-2 bg-background border rounded-md"
                  >
                    <option value="primary">Primary</option>
                    <option value="backup">Backup</option>
                  </select>
                  <button
                    onClick={addMember}
                    disabled={!newMember.user_email}
                    className="px-3 py-2 border rounded-md hover:bg-accent disabled:opacity-50"
                  >
                    Add
                  </button>
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-2 mt-6">
              <button
                onClick={() => setShowCreateModal(false)}
                className="px-4 py-2 border rounded-md hover:bg-accent"
              >
                Cancel
              </button>
              <button
                onClick={handleCreate}
                disabled={isCreating || !newSchedule.name}
                className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
              >
                {isCreating ? 'Creating...' : 'Create Schedule'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Override Modal */}
      {showOverrideModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card rounded-lg p-6 max-w-md w-full mx-4">
            <h2 className="text-lg font-semibold mb-4">Create Schedule Override</h2>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Schedule</label>
                <select
                  value={override.schedule_id}
                  onChange={(e) => setOverride({ ...override, schedule_id: e.target.value })}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                >
                  <option value="">Select schedule...</option>
                  {schedules?.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">Override User Email</label>
                <input
                  type="email"
                  value={override.override_user_email}
                  onChange={(e) =>
                    setOverride({ ...override, override_user_email: e.target.value })
                  }
                  className="w-full px-3 py-2 bg-background border rounded-md"
                  placeholder="substitute@example.com"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-1">Start Time</label>
                  <input
                    type="datetime-local"
                    value={override.start_time}
                    onChange={(e) => setOverride({ ...override, start_time: e.target.value })}
                    className="w-full px-3 py-2 bg-background border rounded-md"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">End Time</label>
                  <input
                    type="datetime-local"
                    value={override.end_time}
                    onChange={(e) => setOverride({ ...override, end_time: e.target.value })}
                    className="w-full px-3 py-2 bg-background border rounded-md"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">Reason</label>
                <input
                  type="text"
                  value={override.reason}
                  onChange={(e) => setOverride({ ...override, reason: e.target.value })}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                  placeholder="Vacation, sick leave, etc."
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 mt-6">
              <button
                onClick={() => setShowOverrideModal(false)}
                className="px-4 py-2 border rounded-md hover:bg-accent"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateOverride}
                disabled={
                  !override.schedule_id ||
                  !override.override_user_email ||
                  !override.start_time ||
                  !override.end_time
                }
                className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
              >
                Create Override
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
