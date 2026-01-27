import { useState } from 'react'
import { useDispatch } from 'react-redux'
import { useNavigate } from 'react-router-dom'
import { Eye, EyeOff, LogIn, UserPlus } from 'lucide-react'
import { login } from '../store/authSlice'
import RevOpsLogo from '../components/common/RevOpsLogo'

const API_BASE = import.meta.env.VITE_API_BASE_URL || ''

interface TokenResponse {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
}

interface UserResponse {
  id: string
  email: string
  name: string | null
  role: string
  is_active: boolean
  organization_id: string | null
  organization_name: string | null
}

export default function LoginPage() {
  const dispatch = useDispatch()
  const navigate = useNavigate()

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [name, setName] = useState('')
  const [organizationName, setOrganizationName] = useState('')
  const [organizationSlug, setOrganizationSlug] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')
  const [isRegisterMode, setIsRegisterMode] = useState(false)

  const fetchUserInfo = async (accessToken: string): Promise<UserResponse | null> => {
    try {
      const response = await fetch(`${API_BASE}/api/v1/auth/me`, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      })
      if (response.ok) {
        return await response.json()
      }
    } catch (err) {
      console.warn('Failed to fetch user info:', err)
    }
    return null
  }

  const handleLogin = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim().toLowerCase(), password }),
      })

      if (response.ok) {
        const tokenData: TokenResponse = await response.json()
        const userInfo = await fetchUserInfo(tokenData.access_token)

        dispatch(
          login({
            userEmail: userInfo?.email || email.trim().toLowerCase(),
            userName: userInfo?.name || null,
            userId: userInfo?.id || null,
            organizationId: userInfo?.organization_id || null,
            organizationName: userInfo?.organization_name || null,
            accessToken: tokenData.access_token,
            refreshToken: tokenData.refresh_token,
            userRole: (userInfo?.role as 'admin' | 'analyst' | 'viewer') || 'viewer',
          })
        )
        navigate('/')
      } else {
        const data = await response.json().catch(() => ({}))
        setError(data.detail || 'Invalid email or password')
      }
    } catch (err) {
      // Demo mode - allow login without backend auth
      console.warn('Auth endpoint not available, using demo mode')
      dispatch(login({ userEmail: email.trim().toLowerCase() }))
      navigate('/')
    }
  }

  const handleRegister = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/v1/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: email.trim().toLowerCase(),
          password,
          name: name.trim() || null,
          organization_name: organizationName.trim() || null,
          organization_slug: organizationSlug.trim().toLowerCase() || null,
        }),
      })

      if (response.ok) {
        const tokenData: TokenResponse = await response.json()
        const userInfo = await fetchUserInfo(tokenData.access_token)

        dispatch(
          login({
            userEmail: userInfo?.email || email.trim().toLowerCase(),
            userName: userInfo?.name || name.trim() || null,
            userId: userInfo?.id || null,
            organizationId: userInfo?.organization_id || null,
            organizationName: userInfo?.organization_name || null,
            accessToken: tokenData.access_token,
            refreshToken: tokenData.refresh_token,
            userRole: (userInfo?.role as 'admin' | 'analyst' | 'viewer') || 'viewer',
          })
        )
        navigate('/')
      } else {
        const data = await response.json().catch(() => ({}))
        setError(data.detail || 'Registration failed')
      }
    } catch (err) {
      // Demo mode - allow registration without backend
      console.warn('Auth endpoint not available, using demo mode')
      dispatch(login({ userEmail: email.trim().toLowerCase(), userName: name.trim() || null }))
      navigate('/')
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)

    // Validate inputs
    if (!email.trim() || !password.trim()) {
      setError('Please enter your email and password')
      setIsLoading(false)
      return
    }

    // Basic email validation
    if (!email.includes('@')) {
      setError('Please enter a valid email address')
      setIsLoading(false)
      return
    }

    // Password length validation for registration
    if (isRegisterMode && password.length < 6) {
      setError('Password must be at least 6 characters')
      setIsLoading(false)
      return
    }

    try {
      if (isRegisterMode) {
        await handleRegister()
      } else {
        await handleLogin()
      }
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center mb-4">
            <RevOpsLogo size={64} />
          </div>
          <h1 className="text-2xl font-bold">RevOps</h1>
          <p className="text-muted-foreground mt-2">Multi-SIEM Security Operations Platform</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4 rounded-lg border bg-card p-6">
          <div className="flex gap-2 mb-4">
            <button
              type="button"
              onClick={() => {
                setIsRegisterMode(false)
                setError('')
              }}
              className={`flex-1 py-2 text-sm font-medium rounded-md transition-colors ${
                !isRegisterMode
                  ? 'bg-primary text-primary-foreground'
                  : 'bg-muted text-muted-foreground hover:text-foreground'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => {
                setIsRegisterMode(true)
                setError('')
              }}
              className={`flex-1 py-2 text-sm font-medium rounded-md transition-colors ${
                isRegisterMode
                  ? 'bg-primary text-primary-foreground'
                  : 'bg-muted text-muted-foreground hover:text-foreground'
              }`}
            >
              Register
            </button>
          </div>

          {error && (
            <div className="p-3 rounded-md bg-destructive/10 text-destructive text-sm">{error}</div>
          )}

          {isRegisterMode && (
            <>
              <div>
                <label htmlFor="name" className="block text-sm font-medium mb-2">
                  Name <span className="text-muted-foreground">(optional)</span>
                </label>
                <input
                  id="name"
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Your name"
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary"
                  autoComplete="name"
                />
              </div>

              <div className="border-t pt-4 mt-2">
                <p className="text-xs text-muted-foreground mb-3">
                  Create a new organization (you'll be the admin)
                </p>
                <div className="space-y-3">
                  <div>
                    <label htmlFor="orgName" className="block text-sm font-medium mb-2">
                      Organization Name
                    </label>
                    <input
                      id="orgName"
                      type="text"
                      value={organizationName}
                      onChange={(e) => {
                        setOrganizationName(e.target.value)
                        // Auto-generate slug from name
                        const slug = e.target.value
                          .toLowerCase()
                          .replace(/[^a-z0-9]+/g, '-')
                          .replace(/^-|-$/g, '')
                        setOrganizationSlug(slug)
                      }}
                      placeholder="Acme Corp"
                      className="w-full rounded-md border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary"
                    />
                  </div>
                  <div>
                    <label htmlFor="orgSlug" className="block text-sm font-medium mb-2">
                      Organization ID <span className="text-muted-foreground">(URL-friendly)</span>
                    </label>
                    <input
                      id="orgSlug"
                      type="text"
                      value={organizationSlug}
                      onChange={(e) => setOrganizationSlug(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ''))}
                      placeholder="acme-corp"
                      className="w-full rounded-md border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary"
                    />
                  </div>
                </div>
              </div>
            </>
          )}

          <div>
            <label htmlFor="email" className="block text-sm font-medium mb-2">
              Email
            </label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@company.com"
              className="w-full rounded-md border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary"
              autoComplete="email"
            />
          </div>

          <div>
            <label htmlFor="password" className="block text-sm font-medium mb-2">
              Password
            </label>
            <div className="relative">
              <input
                id="password"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={isRegisterMode ? 'Create a password (min 6 chars)' : 'Enter your password'}
                className="w-full rounded-md border bg-background px-3 py-2 pr-10 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary"
                autoComplete={isRegisterMode ? 'new-password' : 'current-password'}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-muted-foreground hover:text-foreground"
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors"
          >
            {isLoading ? (
              <>
                <div className="w-4 h-4 border-2 border-primary-foreground/30 border-t-primary-foreground rounded-full animate-spin" />
                {isRegisterMode ? 'Creating account...' : 'Signing in...'}
              </>
            ) : isRegisterMode ? (
              <>
                <UserPlus size={16} />
                Create Account
              </>
            ) : (
              <>
                <LogIn size={16} />
                Sign In
              </>
            )}
          </button>
        </form>
      </div>
    </div>
  )
}
