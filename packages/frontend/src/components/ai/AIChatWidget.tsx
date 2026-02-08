/**
 * AIChatWidget - Floating AI assistant chat widget
 *
 * Features:
 * - Minimizable floating chat window
 * - File drop support for rule conversions
 * - Conversation history
 * - Integration with AI conversion services
 */

import { useState, useRef, useEffect, useCallback } from 'react'
import { useSelector } from 'react-redux'
import {
  MessageSquare,
  X,
  Minus,
  Send,
  Loader2,
  Upload,
  FileCode,
  Sparkles,
  Trash2,
  Copy,
  Check,
  Bot,
  User,
  ChevronDown,
  Paperclip,
  ArrowRightLeft,
  Settings,
  AlertCircle,
} from 'lucide-react'
import { cn } from '../../lib/utils'
import type { RootState } from '../../store'
import { useGetAISettingsQuery } from '../../api/pantherApi'

const API_BASE = import.meta.env.VITE_API_BASE_URL || ''

interface Message {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  timestamp: Date
  attachments?: Array<{
    name: string
    content: string
    type: string
  }>
  isLoading?: boolean
}

interface ChatContext {
  sourceFormat?: string
  targetFormat?: string
  lastConversion?: string
}

export default function AIChatWidget() {
  const { accessToken } = useSelector((state: RootState) => state.auth)
  const [isOpen, setIsOpen] = useState(false)
  const [isMinimized, setIsMinimized] = useState(false)
  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'welcome',
      role: 'assistant',
      content: `Hi! I'm your AI security assistant. I can help you with:

• **Convert detection rules** between SIEM formats (SPL, KQL, YARA-L, Sigma, etc.)
• **Explain rules** - understand what a detection rule does
• **Optimize rules** - get suggestions to improve your rules
• **Answer questions** about security concepts

You can also drag & drop rule files directly into this chat!`,
      timestamp: new Date(),
    },
  ])
  const [inputValue, setInputValue] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [isDragging, setIsDragging] = useState(false)
  const [attachedFiles, setAttachedFiles] = useState<Array<{ name: string; content: string }>>([])
  const [context, setContext] = useState<ChatContext>({})
  const [copiedId, setCopiedId] = useState<string | null>(null)

  const messagesEndRef = useRef<HTMLDivElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const chatContainerRef = useRef<HTMLDivElement>(null)

  // Check if AI credentials are configured (env vars or organization keys)
  const { data: aiSettings } = useGetAISettingsQuery()
  const hasOrgKeys = aiSettings?.organization_keys?.some(k => k.configured) || false
  const isAIConfigured = aiSettings?.openai?.configured || aiSettings?.anthropic?.configured || hasOrgKeys

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  // Handle file drop
  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)

    const files = Array.from(e.dataTransfer.files)
    processFiles(files)
  }, [])

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
  }, [])

  const processFiles = async (files: File[]) => {
    const newAttachments: Array<{ name: string; content: string }> = []

    for (const file of files) {
      if (file.size > 100000) {
        // Skip files larger than 100KB
        continue
      }
      const content = await file.text()
      newAttachments.push({ name: file.name, content })
    }

    setAttachedFiles(prev => [...prev, ...newAttachments])
  }

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      processFiles(Array.from(e.target.files))
    }
  }

  const removeAttachment = (index: number) => {
    setAttachedFiles(prev => prev.filter((_, i) => i !== index))
  }

  const copyToClipboard = async (text: string, messageId: string) => {
    await navigator.clipboard.writeText(text)
    setCopiedId(messageId)
    setTimeout(() => setCopiedId(null), 2000)
  }

  const detectFormat = (content: string): string => {
    // Simple format detection heuristics
    if (content.includes('rule ') && content.includes('events:') && content.includes('condition:')) {
      return 'yaral'
    }
    if (content.includes('index=') || content.includes('| stats') || content.includes('| where')) {
      return 'spl'
    }
    if (content.includes('SecurityEvent') || content.includes('| where') && content.includes('| project')) {
      return 'kql'
    }
    if (content.includes('title:') && content.includes('logsource:') && content.includes('detection:')) {
      return 'sigma'
    }
    if (content.includes('def rule(') || content.includes('def title(')) {
      return 'panther'
    }
    if (content.includes('process where') || content.includes('sequence by')) {
      return 'eql'
    }
    return 'unknown'
  }

  const sendMessage = async () => {
    if (!inputValue.trim() && attachedFiles.length === 0) return

    const userMessage: Message = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: inputValue,
      timestamp: new Date(),
      attachments: attachedFiles.map(f => ({
        name: f.name,
        content: f.content,
        type: detectFormat(f.content),
      })),
    }

    setMessages(prev => [...prev, userMessage])
    setInputValue('')
    setAttachedFiles([])
    setIsLoading(true)

    // Add loading message
    const loadingId = `loading-${Date.now()}`
    setMessages(prev => [
      ...prev,
      {
        id: loadingId,
        role: 'assistant',
        content: '',
        timestamp: new Date(),
        isLoading: true,
      },
    ])

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      }
      if (accessToken) {
        headers['Authorization'] = `Bearer ${accessToken}`
      }

      const response = await fetch(`${API_BASE}/api/v1/ai/chat`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          message: inputValue,
          attachments: userMessage.attachments,
          context,
          history: messages.slice(-10).map(m => ({
            role: m.role,
            content: m.content,
          })),
        }),
      })

      if (response.ok) {
        const data = await response.json()

        // Update context if conversion was performed
        if (data.context) {
          setContext(prev => ({ ...prev, ...data.context }))
        }

        setMessages(prev =>
          prev.map(m =>
            m.id === loadingId
              ? {
                  ...m,
                  content: data.response,
                  isLoading: false,
                }
              : m
          )
        )
      } else {
        throw new Error('Failed to get response')
      }
    } catch (error) {
      // Fallback response if endpoint not available
      const fallbackResponse = generateFallbackResponse(inputValue, userMessage.attachments)

      setMessages(prev =>
        prev.map(m =>
          m.id === loadingId
            ? {
                ...m,
                content: fallbackResponse,
                isLoading: false,
              }
            : m
        )
      )
    } finally {
      setIsLoading(false)
    }
  }

  const generateFallbackResponse = (
    message: string,
    attachments?: Array<{ name: string; content: string; type: string }>
  ): string => {
    const lowerMessage = message.toLowerCase()

    // Check for conversion requests
    if (
      lowerMessage.includes('convert') ||
      lowerMessage.includes('translate') ||
      lowerMessage.includes('transform')
    ) {
      if (attachments && attachments.length > 0) {
        const file = attachments[0]
        return `I detected that your file "${file.name}" appears to be in **${file.type.toUpperCase()}** format.

To convert this rule, please use the **Migration Hub** where you can:
1. Go to the Rule Converter tab
2. Paste your rule or use the Migration Wizard
3. Select your target format

Would you like me to explain what this rule does instead?`
      }
      return `I can help you convert detection rules! Please either:

1. **Drop a file** containing your rule into this chat
2. **Paste the rule** directly in your message
3. Use the **Migration Hub** for bulk conversions

What format would you like to convert from and to?`
    }

    // Check for explanation requests
    if (
      lowerMessage.includes('explain') ||
      lowerMessage.includes('what does') ||
      lowerMessage.includes('understand')
    ) {
      if (attachments && attachments.length > 0) {
        return `I'll analyze the rule from "${attachments[0].name}".

This appears to be a **${attachments[0].type.toUpperCase()}** detection rule. To get a detailed AI-powered explanation:

1. Go to **Migration Hub**
2. Paste your rule in the source editor
3. Click the **Explain** button

The AI will break down:
• What the rule is detecting
• The logic and conditions
• Potential false positive scenarios`
      }
    }

    // Check for optimization requests
    if (
      lowerMessage.includes('optimize') ||
      lowerMessage.includes('improve') ||
      lowerMessage.includes('suggest')
    ) {
      return `I can suggest improvements for your detection rules!

To get AI-powered optimization suggestions:
1. Go to **Migration Hub**
2. Paste your rule
3. Click the **Suggest** button

The AI will analyze your rule and provide:
• Performance optimizations
• Coverage improvements
• Best practice recommendations`
    }

    // Default helpful response
    return `I'm here to help with your security detection needs! Here's what I can assist with:

**Rule Conversion**
Drop a file or paste a rule, and I'll help identify the format and guide you through conversion.

**Rule Explanation**
Share a rule and I'll explain what it detects and how it works.

**Best Practices**
Ask about SIEM-specific syntax, detection strategies, or rule optimization.

**Quick Links:**
• [Migration Hub](/migrate) - Convert rules between formats
• [Connectors](/connectors) - Set up data sources
• [Alerts](/alerts) - View detection alerts

What would you like help with?`
  }

  const clearChat = () => {
    setMessages([
      {
        id: 'welcome',
        role: 'assistant',
        content: `Chat cleared! How can I help you?`,
        timestamp: new Date(),
      },
    ])
    setContext({})
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendMessage()
    }
  }

  // Render minimized button
  if (!isOpen) {
    return (
      <button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-6 right-6 w-14 h-14 rounded-full bg-gradient-to-r from-purple-500 to-blue-500 text-white shadow-lg hover:shadow-xl transition-all hover:scale-105 flex items-center justify-center z-50"
        title="Open AI Assistant"
      >
        <Sparkles size={24} />
      </button>
    )
  }

  // Render minimized bar
  if (isMinimized) {
    return (
      <div
        className="fixed bottom-6 right-6 w-72 bg-card border rounded-lg shadow-lg z-50 cursor-pointer hover:shadow-xl transition-shadow"
        onClick={() => setIsMinimized(false)}
      >
        <div className="flex items-center justify-between p-3">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-full bg-gradient-to-r from-purple-500 to-blue-500 flex items-center justify-center">
              <Sparkles size={16} className="text-white" />
            </div>
            <span className="font-medium">AI Assistant</span>
          </div>
          <div className="flex items-center gap-1">
            <button
              onClick={(e) => {
                e.stopPropagation()
                setIsMinimized(false)
              }}
              className="p-1 hover:bg-accent rounded"
            >
              <ChevronDown size={16} className="rotate-180" />
            </button>
            <button
              onClick={(e) => {
                e.stopPropagation()
                setIsOpen(false)
              }}
              className="p-1 hover:bg-accent rounded text-muted-foreground"
            >
              <X size={16} />
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div
      ref={chatContainerRef}
      className="fixed bottom-6 right-6 w-96 h-[600px] max-h-[80vh] bg-card border rounded-lg shadow-2xl z-50 flex flex-col overflow-hidden"
      onDrop={handleDrop}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
    >
      {/* Header */}
      <div className="flex items-center justify-between p-3 border-b bg-gradient-to-r from-purple-500/10 to-blue-500/10">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-full bg-gradient-to-r from-purple-500 to-blue-500 flex items-center justify-center">
            <Sparkles size={16} className="text-white" />
          </div>
          <div>
            <h3 className="font-semibold text-sm">AI Assistant</h3>
            <p className="text-xs text-muted-foreground">Security detection helper</p>
          </div>
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={clearChat}
            className="p-1.5 hover:bg-accent rounded text-muted-foreground"
            title="Clear chat"
          >
            <Trash2 size={16} />
          </button>
          <button
            onClick={() => setIsMinimized(true)}
            className="p-1.5 hover:bg-accent rounded text-muted-foreground"
            title="Minimize"
          >
            <Minus size={16} />
          </button>
          <button
            onClick={() => setIsOpen(false)}
            className="p-1.5 hover:bg-accent rounded text-muted-foreground"
            title="Close"
          >
            <X size={16} />
          </button>
        </div>
      </div>

      {/* Credentials Warning Banner */}
      {!isAIConfigured && (
        <div className="mx-3 mt-3 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30">
          <div className="flex items-start gap-2">
            <AlertCircle size={18} className="text-amber-500 shrink-0 mt-0.5" />
            <div className="flex-1">
              <p className="text-sm font-medium text-amber-600 dark:text-amber-400">
                AI credentials not configured
              </p>
              <p className="text-xs text-muted-foreground mt-1">
                To use AI features, please configure your OpenAI or Anthropic API key in settings.
              </p>
              <a
                href="/settings/ai"
                className="inline-flex items-center gap-1 mt-2 text-xs text-primary hover:underline"
              >
                <Settings size={12} />
                Go to AI Settings
              </a>
            </div>
          </div>
        </div>
      )}

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-3 space-y-4">
        {/* Drag overlay */}
        {isDragging && (
          <div className="absolute inset-0 bg-primary/10 border-2 border-dashed border-primary rounded-lg flex items-center justify-center z-10 m-2">
            <div className="text-center">
              <Upload size={48} className="mx-auto text-primary mb-2" />
              <p className="font-medium">Drop files here</p>
              <p className="text-sm text-muted-foreground">Supports rule files (.yml, .json, .txt, etc.)</p>
            </div>
          </div>
        )}

        {messages.map((message) => (
          <div
            key={message.id}
            className={cn(
              'flex gap-2',
              message.role === 'user' ? 'flex-row-reverse' : 'flex-row'
            )}
          >
            <div
              className={cn(
                'w-7 h-7 rounded-full flex items-center justify-center shrink-0',
                message.role === 'user'
                  ? 'bg-primary text-primary-foreground'
                  : 'bg-gradient-to-r from-purple-500 to-blue-500 text-white'
              )}
            >
              {message.role === 'user' ? <User size={14} /> : <Bot size={14} />}
            </div>
            <div
              className={cn(
                'max-w-[85%] rounded-lg p-3 text-sm',
                message.role === 'user'
                  ? 'bg-primary text-primary-foreground'
                  : 'bg-muted'
              )}
            >
              {message.isLoading ? (
                <div className="flex items-center gap-2">
                  <Loader2 size={14} className="animate-spin" />
                  <span>Thinking...</span>
                </div>
              ) : (
                <>
                  {/* Attachments */}
                  {message.attachments && message.attachments.length > 0 && (
                    <div className="mb-2 space-y-1">
                      {message.attachments.map((att, i) => (
                        <div
                          key={i}
                          className="flex items-center gap-2 px-2 py-1 rounded bg-background/50 text-xs"
                        >
                          <FileCode size={12} />
                          <span className="truncate">{att.name}</span>
                          <span className="text-muted-foreground">({att.type})</span>
                        </div>
                      ))}
                    </div>
                  )}
                  {/* Message content with markdown-like rendering */}
                  <div className="whitespace-pre-wrap break-words prose prose-sm dark:prose-invert max-w-none">
                    {message.content.split('\n').map((line, i) => {
                      // Bold text
                      const boldProcessed = line.replace(
                        /\*\*(.*?)\*\*/g,
                        '<strong>$1</strong>'
                      )
                      // Links
                      const linkProcessed = boldProcessed.replace(
                        /\[([^\]]+)\]\(([^)]+)\)/g,
                        '<a href="$2" class="text-primary hover:underline">$1</a>'
                      )
                      return (
                        <span
                          key={i}
                          dangerouslySetInnerHTML={{ __html: linkProcessed }}
                        />
                      )
                    }).reduce((acc: React.ReactNode[], elem, i) => {
                      if (i === 0) return [elem]
                      return [...acc, <br key={`br-${i}`} />, elem]
                    }, [])}
                  </div>
                  {/* Copy button for assistant messages */}
                  {message.role === 'assistant' && message.content && (
                    <button
                      onClick={() => copyToClipboard(message.content, message.id)}
                      className="mt-2 flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
                    >
                      {copiedId === message.id ? (
                        <>
                          <Check size={12} />
                          Copied
                        </>
                      ) : (
                        <>
                          <Copy size={12} />
                          Copy
                        </>
                      )}
                    </button>
                  )}
                </>
              )}
            </div>
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      {/* Attached files preview */}
      {attachedFiles.length > 0 && (
        <div className="px-3 py-2 border-t bg-muted/50">
          <div className="flex flex-wrap gap-2">
            {attachedFiles.map((file, index) => (
              <div
                key={index}
                className="flex items-center gap-1 px-2 py-1 rounded-md bg-background border text-xs"
              >
                <FileCode size={12} />
                <span className="truncate max-w-[100px]">{file.name}</span>
                <button
                  onClick={() => removeAttachment(index)}
                  className="ml-1 text-muted-foreground hover:text-destructive"
                >
                  <X size={12} />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Input */}
      <div className="p-3 border-t">
        <div className="flex items-end gap-2">
          <button
            onClick={() => fileInputRef.current?.click()}
            className="p-2 hover:bg-accent rounded-md text-muted-foreground"
            title="Attach file"
          >
            <Paperclip size={18} />
          </button>
          <input
            ref={fileInputRef}
            type="file"
            multiple
            accept=".yml,.yaml,.json,.txt,.spl,.kql,.eql,.py,.sigma"
            onChange={handleFileSelect}
            className="hidden"
          />
          <div className="flex-1 relative">
            <textarea
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask about rules, conversions, or drop files..."
              rows={1}
              className="w-full px-3 py-2 pr-10 rounded-md border bg-background text-sm resize-none focus:outline-none focus:ring-2 focus:ring-primary max-h-32"
              style={{ minHeight: '40px' }}
            />
          </div>
          <button
            onClick={sendMessage}
            disabled={isLoading || (!inputValue.trim() && attachedFiles.length === 0)}
            className="p-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isLoading ? (
              <Loader2 size={18} className="animate-spin" />
            ) : (
              <Send size={18} />
            )}
          </button>
        </div>
        <p className="text-xs text-muted-foreground mt-2 text-center">
          Press Enter to send • Shift+Enter for new line
        </p>
      </div>
    </div>
  )
}
