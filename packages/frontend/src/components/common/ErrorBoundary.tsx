import { Component, ErrorInfo, ReactNode } from 'react'
import { AlertTriangle, RefreshCw } from 'lucide-react'

interface ErrorBoundaryProps {
  children: ReactNode
}

interface ErrorBoundaryState {
  hasError: boolean
  error: Error | null
}

/**
 * Recoverable error boundary. Catches render/lifecycle errors in its subtree
 * and shows a fallback with a Reload action instead of white-screening the app.
 */
export default class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // No dedicated logger in the codebase; fall back to console.error.
    console.error('ErrorBoundary caught an error:', error, errorInfo)
  }

  handleReload = () => {
    window.location.reload()
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex min-h-[60vh] items-center justify-center p-4">
          <div className="w-full max-w-md rounded-lg border border-border bg-card p-6 text-center">
            <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-destructive/10 text-destructive">
              <AlertTriangle size={24} />
            </div>
            <h2 className="mb-2 text-lg font-semibold text-foreground">Something went wrong</h2>
            <p className="mb-4 text-sm text-muted-foreground">
              An unexpected error occurred while rendering this view. You can try reloading the page.
            </p>
            {this.state.error?.message && (
              <p className="mb-4 break-words rounded-md bg-muted px-3 py-2 text-left font-mono text-xs text-muted-foreground">
                {this.state.error.message}
              </p>
            )}
            <button
              onClick={this.handleReload}
              className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
            >
              <RefreshCw size={16} />
              Reload
            </button>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}
