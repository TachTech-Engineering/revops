import { useState } from 'react'
import { useDispatch } from 'react-redux'
import { useNavigate } from 'react-router-dom'
import { Eye, EyeOff, LogIn } from 'lucide-react'
import { login } from '../store/authSlice'
import PantherLogo from '../components/common/PantherLogo'

export default function LoginPage() {
  const dispatch = useDispatch()
  const navigate = useNavigate()

  const [companyName, setCompanyName] = useState('')
  const [pantherToken, setPantherToken] = useState('')
  const [userEmail, setUserEmail] = useState('')
  const [showToken, setShowToken] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')

  // Convert company name to full Panther host
  const getFullHost = (input: string): string => {
    const cleaned = input.trim().toLowerCase()

    // If it already looks like a full URL, extract and use it
    if (cleaned.includes('.')) {
      // Remove protocol if present
      let host = cleaned.replace(/^https?:\/\//, '')
      host = host.replace(/\/$/, '')
      return host
    }

    // Otherwise, construct the full URL from company name
    return `api.${cleaned}.runpanther.net`
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)

    // Validate inputs
    if (!companyName.trim() || !pantherToken.trim() || !userEmail.trim()) {
      setError('Please enter your email, company name, and API token')
      setIsLoading(false)
      return
    }

    // Basic email validation
    if (!userEmail.includes('@')) {
      setError('Please enter a valid email address')
      setIsLoading(false)
      return
    }

    const fullHost = getFullHost(companyName)

    try {
      // Test the connection by making a health check
      const response = await fetch('/api/v1/health', {
        headers: {
          'X-Panther-Host': fullHost,
          'X-Panther-Token': pantherToken.trim(),
        },
      })

      if (response.ok) {
        dispatch(login({ pantherHost: fullHost, pantherToken: pantherToken.trim(), userEmail: userEmail.trim().toLowerCase() }))
        navigate('/')
      } else {
        // Try to get error details from response
        try {
          const data = await response.json()
          setError(data.detail || 'Failed to connect. Please check your credentials.')
        } catch {
          setError('Failed to connect. Please check your credentials.')
        }
      }
    } catch (err) {
      // Network error - backend might not be running
      setError(`Connection error: ${err instanceof Error ? err.message : 'Unable to reach server'}`)
    } finally {
      setIsLoading(false)
    }
  }

  // Show preview of the full host URL
  const hostPreview = companyName.trim() ? getFullHost(companyName) : ''

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center mb-4">
            <PantherLogo size={64} />
          </div>
          <h1 className="text-2xl font-bold">PantherUtil</h1>
          <p className="text-muted-foreground mt-2">Connect to your Panther instance</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4 rounded-lg border bg-card p-6">
          {error && (
            <div className="p-3 rounded-md bg-destructive/10 text-destructive text-sm">
              {error}
            </div>
          )}

          <div>
            <label htmlFor="email" className="block text-sm font-medium mb-2">
              Your Email
            </label>
            <input
              id="email"
              type="email"
              value={userEmail}
              onChange={(e) => setUserEmail(e.target.value)}
              placeholder="you@company.com"
              className="w-full rounded-md border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary"
              autoComplete="email"
            />
            <p className="text-xs text-muted-foreground mt-1">
              Used for audit logging and role-based access
            </p>
          </div>

          <div>
            <label htmlFor="company" className="block text-sm font-medium mb-2">
              Company Name
            </label>
            <input
              id="company"
              type="text"
              value={companyName}
              onChange={(e) => setCompanyName(e.target.value)}
              placeholder="acme"
              className="w-full rounded-md border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary"
              autoComplete="organization"
            />
            {hostPreview && (
              <p className="text-xs text-muted-foreground mt-1">
                Connecting to: <span className="text-foreground font-mono">{hostPreview}</span>
              </p>
            )}
            {!hostPreview && (
              <p className="text-xs text-muted-foreground mt-1">
                Enter your company name (e.g., "acme" for api.acme.runpanther.net)
              </p>
            )}
          </div>

          <div>
            <label htmlFor="token" className="block text-sm font-medium mb-2">
              API Token
            </label>
            <div className="relative">
              <input
                id="token"
                type={showToken ? 'text' : 'password'}
                value={pantherToken}
                onChange={(e) => setPantherToken(e.target.value)}
                placeholder="Enter your Panther API token"
                className="w-full rounded-md border bg-background px-3 py-2 pr-10 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary"
                autoComplete="current-password"
              />
              <button
                type="button"
                onClick={() => setShowToken(!showToken)}
                className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-muted-foreground hover:text-foreground"
              >
                {showToken ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Generate an API token in Panther Settings &gt; API Tokens
            </p>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors"
          >
            {isLoading ? (
              <>
                <div className="w-4 h-4 border-2 border-primary-foreground/30 border-t-primary-foreground rounded-full animate-spin" />
                Connecting...
              </>
            ) : (
              <>
                <LogIn size={16} />
                Connect
              </>
            )}
          </button>
        </form>

      </div>
    </div>
  )
}
