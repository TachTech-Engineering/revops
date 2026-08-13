import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { AlertTriangle, CheckCircle2, Info, X, XCircle } from 'lucide-react'
import { cn } from '../../lib/utils'

/**
 * Minimal toast layer. Mounted once at the app root (see `App.tsx`); any
 * component can raise user-visible feedback with `useToast()`.
 *
 * Deliberately dependency-free and small: a stack of dismissable messages in
 * the bottom-right corner, auto-expiring unless it is an error.
 */

export type ToastVariant = 'success' | 'error' | 'warning' | 'info'

interface ToastItem {
  id: number
  variant: ToastVariant
  message: string
}

interface ToastApi {
  notify: (message: string, variant?: ToastVariant) => void
  success: (message: string) => void
  error: (message: string) => void
  warning: (message: string) => void
  info: (message: string) => void
  dismiss: (id: number) => void
}

const ToastContext = createContext<ToastApi | null>(null)

const AUTO_DISMISS_MS: Record<ToastVariant, number> = {
  success: 4000,
  info: 5000,
  warning: 8000,
  // Errors stay until dismissed: they usually need a decision, not a glance.
  error: 0,
}

const variantStyles: Record<ToastVariant, { wrapper: string; icon: ReactNode }> = {
  success: {
    wrapper: 'border-green-500/40 bg-green-500/10 text-green-500',
    icon: <CheckCircle2 size={16} className="mt-0.5 flex-shrink-0" />,
  },
  error: {
    wrapper: 'border-red-500/40 bg-red-500/10 text-red-500',
    icon: <XCircle size={16} className="mt-0.5 flex-shrink-0" />,
  },
  warning: {
    wrapper: 'border-yellow-500/40 bg-yellow-500/10 text-yellow-500',
    icon: <AlertTriangle size={16} className="mt-0.5 flex-shrink-0" />,
  },
  info: {
    wrapper: 'border-blue-500/40 bg-blue-500/10 text-blue-500',
    icon: <Info size={16} className="mt-0.5 flex-shrink-0" />,
  },
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([])
  const nextId = useRef(1)
  const timers = useRef<Map<number, ReturnType<typeof setTimeout>>>(new Map())

  const dismiss = useCallback((id: number) => {
    const timer = timers.current.get(id)
    if (timer) {
      clearTimeout(timer)
      timers.current.delete(id)
    }
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  const notify = useCallback(
    (message: string, variant: ToastVariant = 'info') => {
      const id = nextId.current++
      setToasts((prev) => [...prev.slice(-3), { id, variant, message }])

      const ttl = AUTO_DISMISS_MS[variant]
      if (ttl > 0) {
        timers.current.set(
          id,
          setTimeout(() => dismiss(id), ttl)
        )
      }
    },
    [dismiss]
  )

  // Clear pending timers if the provider ever unmounts.
  useEffect(() => {
    const pending = timers.current
    return () => {
      pending.forEach((timer) => clearTimeout(timer))
      pending.clear()
    }
  }, [])

  const api = useMemo<ToastApi>(
    () => ({
      notify,
      success: (message: string) => notify(message, 'success'),
      error: (message: string) => notify(message, 'error'),
      warning: (message: string) => notify(message, 'warning'),
      info: (message: string) => notify(message, 'info'),
      dismiss,
    }),
    [notify, dismiss]
  )

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div
        className="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-2"
        aria-live="polite"
        aria-atomic="false"
      >
        {toasts.map((toast) => (
          <div
            key={toast.id}
            role={toast.variant === 'error' ? 'alert' : 'status'}
            className={cn(
              'pointer-events-auto flex items-start gap-2 rounded-lg border p-3 text-sm shadow-lg backdrop-blur',
              variantStyles[toast.variant].wrapper
            )}
          >
            {variantStyles[toast.variant].icon}
            <span className="flex-1 break-words">{toast.message}</span>
            <button
              type="button"
              onClick={() => dismiss(toast.id)}
              aria-label="Dismiss notification"
              className="flex-shrink-0 rounded p-0.5 opacity-70 transition-opacity hover:opacity-100"
            >
              <X size={14} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext)
  if (!ctx) {
    throw new Error('useToast must be used inside a <ToastProvider>')
  }
  return ctx
}
