import { useState, useRef, useEffect } from 'react'
import { MessageSquare, Send, Edit2, Trash2, Reply, ChevronDown, ChevronRight } from 'lucide-react'
import {
  useListNotesQuery,
  useGetNoteRepliesQuery,
  useCreateNoteMutation,
  useUpdateNoteMutation,
  useDeleteNoteMutation,
  type NoteResponse,
  type NoteResourceType,
} from '../../api/pantherApi'
import { cn } from '../../lib/utils'
import { useSelector } from 'react-redux'
import { RootState } from '../../store'

interface NotesPanelProps {
  resourceType: NoteResourceType
  resourceId: string
}

export default function NotesPanel({ resourceType, resourceId }: NotesPanelProps) {
  const [newNote, setNewNote] = useState('')
  const [editingNoteId, setEditingNoteId] = useState<string | null>(null)
  const [editContent, setEditContent] = useState('')
  const [replyingToId, setReplyingToId] = useState<string | null>(null)
  const [replyContent, setReplyContent] = useState('')
  const [expandedReplies, setExpandedReplies] = useState<Set<string>>(new Set())

  const { userEmail } = useSelector((state: RootState) => state.auth)
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  const { data: notes, isLoading } = useListNotesQuery({
    resourceType,
    resourceId,
    includeReplies: false,
  })
  const [createNote] = useCreateNoteMutation()
  const [updateNote] = useUpdateNoteMutation()
  const [deleteNote] = useDeleteNoteMutation()

  const handleSubmit = async () => {
    if (!newNote.trim()) return

    try {
      await createNote({
        resource_type: resourceType,
        resource_id: resourceId,
        content: newNote,
      }).unwrap()
      setNewNote('')
    } catch (error) {
      console.error('Failed to create note:', error)
    }
  }

  const handleUpdate = async (noteId: string) => {
    if (!editContent.trim()) return

    try {
      await updateNote({ id: noteId, content: editContent }).unwrap()
      setEditingNoteId(null)
      setEditContent('')
    } catch (error) {
      console.error('Failed to update note:', error)
    }
  }

  const handleDelete = async (noteId: string) => {
    if (!confirm('Are you sure you want to delete this note?')) return

    try {
      await deleteNote(noteId).unwrap()
    } catch (error) {
      console.error('Failed to delete note:', error)
    }
  }

  const handleReply = async (parentId: string) => {
    if (!replyContent.trim()) return

    try {
      await createNote({
        resource_type: resourceType,
        resource_id: resourceId,
        content: replyContent,
        parent_id: parentId,
      }).unwrap()
      setReplyingToId(null)
      setReplyContent('')
      // Expand replies after adding one
      setExpandedReplies((prev) => new Set([...prev, parentId]))
    } catch (error) {
      console.error('Failed to create reply:', error)
    }
  }

  const toggleReplies = (noteId: string) => {
    setExpandedReplies((prev) => {
      const newSet = new Set(prev)
      if (newSet.has(noteId)) {
        newSet.delete(noteId)
      } else {
        newSet.add(noteId)
      }
      return newSet
    })
  }

  const startEdit = (note: NoteResponse) => {
    setEditingNoteId(note.id)
    setEditContent(note.content)
  }

  const highlightMentions = (content: string) => {
    return content.replace(/@(\S+)/g, '<span class="text-blue-600 dark:text-blue-400 font-medium">@$1</span>')
  }

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffMins = Math.floor(diffMs / 60000)
    const diffHours = Math.floor(diffMins / 60)
    const diffDays = Math.floor(diffHours / 24)

    if (diffMins < 1) return 'just now'
    if (diffMins < 60) return `${diffMins}m ago`
    if (diffHours < 24) return `${diffHours}h ago`
    if (diffDays < 7) return `${diffDays}d ago`
    return date.toLocaleDateString()
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
      <div className="p-4 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center gap-2">
          <MessageSquare className="w-5 h-5 text-gray-500" />
          <h3 className="font-semibold text-gray-900 dark:text-white">Notes</h3>
          {notes && notes.length > 0 && (
            <span className="text-sm text-gray-500">({notes.length})</span>
          )}
        </div>
      </div>

      <div className="p-4 space-y-4">
        {/* New note input */}
        <div className="space-y-2">
          <textarea
            ref={textareaRef}
            value={newNote}
            onChange={(e) => setNewNote(e.target.value)}
            placeholder="Add a note... Use @email to mention someone"
            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 resize-none"
            rows={2}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && e.metaKey) {
                e.preventDefault()
                handleSubmit()
              }
            }}
          />
          <div className="flex justify-between items-center">
            <span className="text-xs text-gray-500">Cmd+Enter to submit</span>
            <button
              onClick={handleSubmit}
              disabled={!newNote.trim()}
              className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm"
            >
              <Send className="w-4 h-4" />
              Add Note
            </button>
          </div>
        </div>

        {/* Notes list */}
        {isLoading ? (
          <div className="flex justify-center py-4">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500" />
          </div>
        ) : notes && notes.length > 0 ? (
          <div className="space-y-4">
            {notes.map((note) => (
              <NoteItem
                key={note.id}
                note={note}
                userEmail={userEmail || ''}
                isEditing={editingNoteId === note.id}
                editContent={editContent}
                onEditContentChange={setEditContent}
                onStartEdit={() => startEdit(note)}
                onCancelEdit={() => setEditingNoteId(null)}
                onSaveEdit={() => handleUpdate(note.id)}
                onDelete={() => handleDelete(note.id)}
                isReplying={replyingToId === note.id}
                replyContent={replyContent}
                onReplyContentChange={setReplyContent}
                onStartReply={() => setReplyingToId(note.id)}
                onCancelReply={() => setReplyingToId(null)}
                onSubmitReply={() => handleReply(note.id)}
                showReplies={expandedReplies.has(note.id)}
                onToggleReplies={() => toggleReplies(note.id)}
                highlightMentions={highlightMentions}
                formatDate={formatDate}
              />
            ))}
          </div>
        ) : (
          <p className="text-center text-gray-500 dark:text-gray-400 py-4">
            No notes yet. Be the first to add one!
          </p>
        )}
      </div>
    </div>
  )
}

interface NoteItemProps {
  note: NoteResponse
  userEmail: string
  isEditing: boolean
  editContent: string
  onEditContentChange: (content: string) => void
  onStartEdit: () => void
  onCancelEdit: () => void
  onSaveEdit: () => void
  onDelete: () => void
  isReplying: boolean
  replyContent: string
  onReplyContentChange: (content: string) => void
  onStartReply: () => void
  onCancelReply: () => void
  onSubmitReply: () => void
  showReplies: boolean
  onToggleReplies: () => void
  highlightMentions: (content: string) => string
  formatDate: (date: string) => string
}

function NoteItem({
  note,
  userEmail,
  isEditing,
  editContent,
  onEditContentChange,
  onStartEdit,
  onCancelEdit,
  onSaveEdit,
  onDelete,
  isReplying,
  replyContent,
  onReplyContentChange,
  onStartReply,
  onCancelReply,
  onSubmitReply,
  showReplies,
  onToggleReplies,
  highlightMentions,
  formatDate,
}: NoteItemProps) {
  const isOwner = note.created_by.toLowerCase() === userEmail.toLowerCase()

  return (
    <div className="border border-gray-200 dark:border-gray-700 rounded-lg">
      <div className="p-3">
        {/* Header */}
        <div className="flex items-start justify-between mb-2">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900/30 flex items-center justify-center">
              <span className="text-sm font-medium text-blue-600 dark:text-blue-400">
                {note.created_by.charAt(0).toUpperCase()}
              </span>
            </div>
            <div>
              <span className="text-sm font-medium text-gray-900 dark:text-white">
                {note.created_by}
              </span>
              <div className="flex items-center gap-2 text-xs text-gray-500">
                <span>{formatDate(note.created_at)}</span>
                {note.is_edited && <span>(edited)</span>}
              </div>
            </div>
          </div>

          {isOwner && !isEditing && (
            <div className="flex items-center gap-1">
              <button
                onClick={onStartEdit}
                className="p-1 text-gray-400 hover:text-blue-600 dark:hover:text-blue-400"
              >
                <Edit2 className="w-4 h-4" />
              </button>
              <button
                onClick={onDelete}
                className="p-1 text-gray-400 hover:text-red-600 dark:hover:text-red-400"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>

        {/* Content */}
        {isEditing ? (
          <div className="space-y-2">
            <textarea
              value={editContent}
              onChange={(e) => onEditContentChange(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 resize-none"
              rows={3}
            />
            <div className="flex justify-end gap-2">
              <button
                onClick={onCancelEdit}
                className="px-3 py-1 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
              >
                Cancel
              </button>
              <button
                onClick={onSaveEdit}
                className="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700"
              >
                Save
              </button>
            </div>
          </div>
        ) : (
          <div
            className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap"
            dangerouslySetInnerHTML={{ __html: highlightMentions(note.content) }}
          />
        )}

        {/* Actions */}
        {!isEditing && (
          <div className="mt-3 flex items-center gap-4">
            <button
              onClick={onStartReply}
              className="flex items-center gap-1 text-sm text-gray-500 hover:text-blue-600 dark:hover:text-blue-400"
            >
              <Reply className="w-4 h-4" />
              Reply
            </button>
            {(note.reply_count || 0) > 0 && (
              <button
                onClick={onToggleReplies}
                className="flex items-center gap-1 text-sm text-gray-500 hover:text-gray-700 dark:hover:text-gray-300"
              >
                {showReplies ? (
                  <ChevronDown className="w-4 h-4" />
                ) : (
                  <ChevronRight className="w-4 h-4" />
                )}
                {note.reply_count} {note.reply_count === 1 ? 'reply' : 'replies'}
              </button>
            )}
          </div>
        )}

        {/* Reply input */}
        {isReplying && (
          <div className="mt-3 space-y-2">
            <textarea
              value={replyContent}
              onChange={(e) => onReplyContentChange(e.target.value)}
              placeholder="Write a reply..."
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 resize-none text-sm"
              rows={2}
              autoFocus
            />
            <div className="flex justify-end gap-2">
              <button
                onClick={onCancelReply}
                className="px-3 py-1 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
              >
                Cancel
              </button>
              <button
                onClick={onSubmitReply}
                disabled={!replyContent.trim()}
                className="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
              >
                Reply
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Replies */}
      {showReplies && <NoteReplies noteId={note.id} userEmail={userEmail} formatDate={formatDate} highlightMentions={highlightMentions} />}
    </div>
  )
}

function NoteReplies({
  noteId,
  userEmail,
  formatDate,
  highlightMentions,
}: {
  noteId: string
  userEmail: string
  formatDate: (date: string) => string
  highlightMentions: (content: string) => string
}) {
  const { data: replies, isLoading } = useGetNoteRepliesQuery(noteId)

  if (isLoading) {
    return (
      <div className="px-4 pb-3">
        <div className="animate-pulse h-12 bg-gray-100 dark:bg-gray-700 rounded" />
      </div>
    )
  }

  if (!replies || replies.length === 0) return null

  return (
    <div className="border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/30 px-4 py-3 space-y-3">
      {replies.map((reply) => (
        <div key={reply.id} className="flex gap-2">
          <div className="w-6 h-6 rounded-full bg-gray-200 dark:bg-gray-600 flex items-center justify-center flex-shrink-0">
            <span className="text-xs font-medium text-gray-600 dark:text-gray-400">
              {reply.created_by.charAt(0).toUpperCase()}
            </span>
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-gray-900 dark:text-white">
                {reply.created_by}
              </span>
              <span className="text-xs text-gray-500">{formatDate(reply.created_at)}</span>
            </div>
            <div
              className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap"
              dangerouslySetInnerHTML={{ __html: highlightMentions(reply.content) }}
            />
          </div>
        </div>
      ))}
    </div>
  )
}
