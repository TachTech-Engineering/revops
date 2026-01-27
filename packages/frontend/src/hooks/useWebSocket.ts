import { useEffect, useRef, useState, useCallback } from 'react'

export interface WebSocketMessage {
  type: string
  data?: unknown
}

export interface AlertNotification {
  id: string
  title: string
  severity: string
  status: string
  createdAt: string
  ruleName?: string
}

interface UseWebSocketOptions {
  url: string
  onMessage?: (message: WebSocketMessage) => void
  onAlert?: (alert: AlertNotification) => void
  reconnectInterval?: number
  maxReconnectAttempts?: number
}

interface UseWebSocketReturn {
  isConnected: boolean
  lastMessage: WebSocketMessage | null
  sendMessage: (message: unknown) => void
  reconnect: () => void
}

export function useWebSocket({
  url,
  onMessage,
  onAlert,
  reconnectInterval = 5000,
  maxReconnectAttempts = 10,
}: UseWebSocketOptions): UseWebSocketReturn {
  const [isConnected, setIsConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectAttemptsRef = useRef(0)
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return
    }

    try {
      const ws = new WebSocket(url)

      ws.onopen = () => {
        setIsConnected(true)
        reconnectAttemptsRef.current = 0
        console.log('WebSocket connected')
      }

      ws.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data)
          setLastMessage(message)

          if (message.type === 'new_alert' && message.data && onAlert) {
            onAlert(message.data as AlertNotification)
          }

          if (onMessage) {
            onMessage(message)
          }
        } catch (e) {
          console.error('Failed to parse WebSocket message:', e)
        }
      }

      ws.onclose = () => {
        setIsConnected(false)
        console.log('WebSocket disconnected')

        // Attempt reconnect
        if (reconnectAttemptsRef.current < maxReconnectAttempts) {
          reconnectAttemptsRef.current += 1
          reconnectTimeoutRef.current = setTimeout(() => {
            console.log(`Reconnecting... (attempt ${reconnectAttemptsRef.current})`)
            connect()
          }, reconnectInterval)
        }
      }

      ws.onerror = (error) => {
        console.error('WebSocket error:', error)
      }

      wsRef.current = ws
    } catch (e) {
      console.error('Failed to create WebSocket:', e)
    }
  }, [url, onMessage, onAlert, reconnectInterval, maxReconnectAttempts])

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
    }
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }
    setIsConnected(false)
  }, [])

  const sendMessage = useCallback((message: unknown) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message))
    }
  }, [])

  const reconnect = useCallback(() => {
    disconnect()
    reconnectAttemptsRef.current = 0
    connect()
  }, [connect, disconnect])

  useEffect(() => {
    connect()

    // Send periodic pings to keep connection alive
    const pingInterval = setInterval(() => {
      sendMessage({ type: 'ping' })
    }, 25000)

    return () => {
      clearInterval(pingInterval)
      disconnect()
    }
  }, [connect, disconnect, sendMessage])

  return {
    isConnected,
    lastMessage,
    sendMessage,
    reconnect,
  }
}

export function useAlertWebSocket(onAlert?: (alert: AlertNotification) => void) {
  // Use API base URL if set, otherwise fall back to window.location
  const apiBaseUrl = import.meta.env.VITE_API_BASE_URL || ''
  let wsUrl: string

  if (apiBaseUrl) {
    // Convert http(s) URL to ws(s) URL
    const url = new URL(apiBaseUrl)
    const wsProtocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
    wsUrl = `${wsProtocol}//${url.host}/api/v1/ws/alerts`
  } else {
    wsUrl = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/api/v1/ws/alerts`
  }

  return useWebSocket({
    url: wsUrl,
    onAlert,
  })
}
