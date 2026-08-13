import { useState, useEffect } from 'react'
import { useDispatch } from 'react-redux'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Eye, EyeOff, LogIn, UserPlus, ArrowLeft, KeyRound, Mail } from 'lucide-react'
import { login } from '../store/authSlice'
import RevOpsLogo from '../components/common/RevOpsLogo'

const API_BASE = import.meta.env.VITE_API_BASE_URL || ''

const NETWORK_ERROR_MESSAGE =
  'Unable to reach the server. Check your connection and try again.'

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

interface SSOProvider {
  id: string
  provider?: string
  name: string
  icon: string
}

interface SSODetectionResult {
  sso_available: boolean
  organization_id?: string
  organization_name?: string
  provider?: SSOProvider
}

type AuthMode = 'login' | 'register' | 'forgot' | 'reset'

// Google SVG icon
const GoogleIcon = () => (
  <svg viewBox="0 0 24 24" width="18" height="18" className="flex-shrink-0">
    <path
      fill="#4285F4"
      d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
    />
    <path
      fill="#34A853"
      d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
    />
    <path
      fill="#FBBC05"
      d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
    />
    <path
      fill="#EA4335"
      d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
    />
  </svg>
)

// Okta SVG icon
const OktaIcon = () => (
  <svg viewBox="0 0 24 24" width="18" height="18" className="flex-shrink-0">
    <path
      fill="#007DC1"
      d="M12 0C5.389 0 0 5.389 0 12s5.389 12 12 12 12-5.389 12-12S18.611 0 12 0zm0 18c-3.314 0-6-2.686-6-6s2.686-6 6-6 6 2.686 6 6-2.686 6-6 6z"
    />
  </svg>
)

// Microsoft/Azure AD icon
const MicrosoftIcon = () => (
  <svg viewBox="0 0 24 24" width="18" height="18" className="flex-shrink-0">
    <path fill="#F25022" d="M1 1h10v10H1z" />
    <path fill="#00A4EF" d="M1 13h10v10H1z" />
    <path fill="#7FBA00" d="M13 1h10v10H13z" />
    <path fill="#FFB900" d="M13 13h10v10H13z" />
  </svg>
)

const getProviderIcon = (icon: string) => {
  switch (icon) {
    case 'google':
      return <GoogleIcon />
    case 'okta':
      return <OktaIcon />
    case 'azure_ad':
      return <MicrosoftIcon />
    default:
      return <KeyRound size={18} />
  }
}

export default function LoginPage() {
  const dispatch = useDispatch()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [name, setName] = useState('')
  const [organizationName, setOrganizationName] = useState('')
  const [organizationSlug, setOrganizationSlug] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [mode, setMode] = useState<AuthMode>(() => {
    // Check if we have a reset token in the URL
    const resetToken = searchParams.get('reset_token')
    return resetToken ? 'reset' : 'login'
  })
  const [resetToken, setResetToken] = useState(() => searchParams.get('reset_token') || '')
  const [ssoProviders, setSsoProviders] = useState<SSOProvider[]>([])
  const [ssoLoading, setSsoLoading] = useState<string | null>(null)
  const [detectedSSO, setDetectedSSO] = useState<SSODetectionResult | null>(null)
  const [ssoDetecting, setSsoDetecting] = useState(false)

  const isRegisterMode = mode === 'register'

  // Debounced email SSO detection
  useEffect(() => {
    if (!email.includes('@') || mode !== 'login') {
      setDetectedSSO(null)
      return
    }

    const timer = setTimeout(async () => {
      setSsoDetecting(true)
      try {
        const response = await fetch(`${API_BASE}/api/v1/auth/sso/detect?email=${encodeURIComponent(email)}`)
        if (response.ok) {
          const data: SSODetectionResult = await response.json()
          if (data.sso_available) {
            setDetectedSSO(data)
          } else {
            setDetectedSSO(null)
          }
        }
      } catch (err) {
        // SSO detection not available
        setDetectedSSO(null)
      } finally {
        setSsoDetecting(false)
      }
    }, 500) // Debounce 500ms

    return () => clearTimeout(timer)
  }, [email, mode])

  // Fetch available SSO providers on mount (global providers)
  useEffect(() => {
    const fetchSSOProviders = async () => {
      try {
        const response = await fetch(`${API_BASE}/api/v1/auth/sso/providers`)
        if (response.ok) {
          const data = await response.json()
          setSsoProviders(data.providers || [])
        }
      } catch (err) {
        // SSO not available, that's fine
        console.debug('SSO providers not available')
      }
    }
    fetchSSOProviders()
  }, [])

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
      // Never fake a session here: a session without tokens 401s on every
      // request and bounces the user back to /login with no explanation.
      console.error('Login request failed:', err)
      setError(NETWORK_ERROR_MESSAGE)
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
      // Same rule as login: no account was created, so do not sign anyone in.
      console.error('Registration request failed:', err)
      setError(NETWORK_ERROR_MESSAGE)
    }
  }

  const handleForgotPassword = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/v1/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim().toLowerCase() }),
      })

      if (response.ok) {
        const data = await response.json()
        setSuccess('If an account with that email exists, a password reset link has been sent.')
        // In development, the token is returned in the response
        if (data.reset_token) {
          console.log('Reset token (dev only):', data.reset_token)
          setSuccess(`Password reset link: ${window.location.origin}/login?reset_token=${data.reset_token}`)
        }
      } else {
        const data = await response.json().catch(() => ({}))
        setError(data.detail || 'Failed to send reset email')
      }
    } catch (err) {
      setError('Unable to connect to server')
    }
  }

  const handleResetPassword = async () => {
    if (password !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    if (password.length < 6) {
      setError('Password must be at least 6 characters')
      return
    }

    try {
      const response = await fetch(`${API_BASE}/api/v1/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: resetToken, new_password: password }),
      })

      if (response.ok) {
        setSuccess('Password has been reset successfully. You can now sign in.')
        setPassword('')
        setConfirmPassword('')
        setResetToken('')
        setTimeout(() => {
          setMode('login')
          setSuccess('')
        }, 2000)
      } else {
        const data = await response.json().catch(() => ({}))
        setError(data.detail || 'Invalid or expired reset token')
      }
    } catch (err) {
      setError('Unable to connect to server')
    }
  }

  const handleSSOLogin = (provider: string) => {
    setSsoLoading(provider)
    // Redirect to SSO authorize endpoint
    // The backend will redirect to the provider's login page
    const redirectUri = encodeURIComponent(window.location.origin)
    window.location.href = `${API_BASE}/api/v1/auth/sso/${provider}/authorize?redirect_uri=${redirectUri}`
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    setIsLoading(true)

    // Forgot password mode - only need email
    if (mode === 'forgot') {
      if (!email.trim() || !email.includes('@')) {
        setError('Please enter a valid email address')
        setIsLoading(false)
        return
      }
      try {
        await handleForgotPassword()
      } finally {
        setIsLoading(false)
      }
      return
    }

    // Reset password mode - need password and confirm
    if (mode === 'reset') {
      try {
        await handleResetPassword()
      } finally {
        setIsLoading(false)
      }
      return
    }

    // Login/Register modes
    if (!email.trim() || !password.trim()) {
      setError('Please enter your email and password')
      setIsLoading(false)
      return
    }

    if (!email.includes('@')) {
      setError('Please enter a valid email address')
      setIsLoading(false)
      return
    }

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
    <div className="dark min-h-screen bg-zinc-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center mb-4">
            <RevOpsLogo size={64} />
          </div>
          <h1 className="text-2xl font-bold text-zinc-100">RevOps</h1>
          <p className="text-zinc-400 mt-2">One Platform. All Your Security Alerts.</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4 rounded-lg border border-zinc-800 bg-zinc-900 p-6 shadow-xl">
          {/* Mode header for forgot/reset */}
          {(mode === 'forgot' || mode === 'reset') ? (
            <div className="mb-4">
              <button
                type="button"
                onClick={() => {
                  setMode('login')
                  setError('')
                  setSuccess('')
                }}
                className="flex items-center gap-1 text-sm text-zinc-400 hover:text-zinc-200 mb-3"
              >
                <ArrowLeft size={16} />
                Back to sign in
              </button>
              <h2 className="text-lg font-semibold text-zinc-100">
                {mode === 'forgot' ? 'Reset your password' : 'Create new password'}
              </h2>
              <p className="text-sm text-zinc-400 mt-1">
                {mode === 'forgot'
                  ? "Enter your email and we'll send you a reset link."
                  : 'Enter your new password below.'}
              </p>
            </div>
          ) : (
            <div className="flex gap-2 mb-4">
              <button
                type="button"
                onClick={() => {
                  setMode('login')
                  setError('')
                  setSuccess('')
                }}
                className={`flex-1 py-2 text-sm font-medium rounded-md transition-colors ${
                  mode === 'login'
                    ? 'bg-blue-600 text-white'
                    : 'bg-zinc-800 text-zinc-400 hover:text-zinc-200'
                }`}
              >
                Sign In
              </button>
              <button
                type="button"
                onClick={() => {
                  setMode('register')
                  setError('')
                  setSuccess('')
                }}
                className={`flex-1 py-2 text-sm font-medium rounded-md transition-colors ${
                  mode === 'register'
                    ? 'bg-blue-600 text-white'
                    : 'bg-zinc-800 text-zinc-400 hover:text-zinc-200'
                }`}
              >
                Register
              </button>
            </div>
          )}

          {error && (
            <div className="p-3 rounded-md bg-red-500/10 text-red-400 text-sm">{error}</div>
          )}

          {success && (
            <div className="p-3 rounded-md bg-green-500/10 text-green-400 text-sm">{success}</div>
          )}

          {isRegisterMode && (
            <>
              <div>
                <label htmlFor="name" className="block text-sm font-medium text-zinc-200 mb-2">
                  Name <span className="text-zinc-500">(optional)</span>
                </label>
                <input
                  id="name"
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Your name"
                  className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  autoComplete="name"
                />
              </div>

              <div className="border-t border-zinc-700 pt-4 mt-2">
                <p className="text-xs text-zinc-400 mb-3">
                  Create a new organization (you'll be the admin)
                </p>
                <div className="space-y-3">
                  <div>
                    <label htmlFor="orgName" className="block text-sm font-medium text-zinc-200 mb-2">
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
                      className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>
                  <div>
                    <label htmlFor="orgSlug" className="block text-sm font-medium text-zinc-200 mb-2">
                      Organization ID <span className="text-zinc-500">(URL-friendly)</span>
                    </label>
                    <input
                      id="orgSlug"
                      type="text"
                      value={organizationSlug}
                      onChange={(e) => setOrganizationSlug(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ''))}
                      placeholder="acme-corp"
                      className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>
                </div>
              </div>
            </>
          )}

          {/* Email field - shown for login, register, forgot */}
          {mode !== 'reset' && (
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-zinc-200 mb-2">
                Email
              </label>
              <div className="relative">
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@company.com"
                  className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 pl-10 text-sm text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  autoComplete="email"
                />
                <Mail size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
              </div>
            </div>
          )}

          {/* Password field - shown for login (when no SSO), register, reset */}
          {mode !== 'forgot' && !(mode === 'login' && detectedSSO) && (
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-zinc-200 mb-2">
                {mode === 'reset' ? 'New Password' : 'Password'}
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={mode === 'register' || mode === 'reset' ? 'Create a password (min 6 chars)' : 'Enter your password'}
                  className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 pl-10 pr-10 text-sm text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                />
                <KeyRound size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-zinc-400 hover:text-zinc-200"
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>
          )}

          {/* Confirm password - only for reset mode */}
          {mode === 'reset' && (
            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-zinc-200 mb-2">
                Confirm Password
              </label>
              <div className="relative">
                <input
                  id="confirmPassword"
                  type={showPassword ? 'text' : 'password'}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Confirm your new password"
                  className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 pl-10 text-sm text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  autoComplete="new-password"
                />
                <KeyRound size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
              </div>
            </div>
          )}

          {/* Forgot password link - only for login mode when no SSO */}
          {mode === 'login' && !detectedSSO && (
            <div className="text-right">
              <button
                type="button"
                onClick={() => {
                  setMode('forgot')
                  setError('')
                  setSuccess('')
                }}
                className="text-sm text-blue-400 hover:text-blue-300"
              >
                Forgot password?
              </button>
            </div>
          )}

          {/* Submit button - hidden for login when SSO is detected */}
          {!(mode === 'login' && detectedSSO) && (
            <button
              type="submit"
              disabled={isLoading}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-md text-sm font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              {isLoading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  {mode === 'forgot' && 'Sending reset link...'}
                  {mode === 'reset' && 'Resetting password...'}
                  {mode === 'register' && 'Creating account...'}
                  {mode === 'login' && 'Signing in...'}
                </>
              ) : (
                <>
                  {mode === 'forgot' && (
                    <>
                      <Mail size={16} />
                      Send Reset Link
                    </>
                  )}
                  {mode === 'reset' && (
                    <>
                      <KeyRound size={16} />
                      Reset Password
                    </>
                  )}
                  {mode === 'register' && (
                    <>
                      <UserPlus size={16} />
                      Create Account
                    </>
                  )}
                  {mode === 'login' && (
                    <>
                      <LogIn size={16} />
                      Sign In
                    </>
                  )}
                </>
              )}
            </button>
          )}

          {/* Detected SSO from email domain */}
          {detectedSSO && detectedSSO.provider && mode === 'login' && (
            <div className="mt-4 p-4 rounded-lg border border-blue-500/30 bg-blue-500/10">
              <p className="text-sm text-blue-400 mb-3">
                {detectedSSO.organization_name} uses Single Sign-On
              </p>
              <button
                type="button"
                onClick={() => handleSSOLogin(detectedSSO.provider!.id)}
                disabled={ssoLoading !== null}
                className="w-full flex items-center justify-center gap-3 px-4 py-2.5 bg-blue-600 text-white rounded-md text-sm font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors"
              >
                {ssoLoading === detectedSSO.provider.id ? (
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                ) : (
                  getProviderIcon(detectedSSO.provider.icon)
                )}
                <span>
                  {ssoLoading === detectedSSO.provider.id
                    ? 'Redirecting...'
                    : `Sign in with ${detectedSSO.provider.name}`}
                </span>
              </button>
            </div>
          )}

          {/* SSO detecting indicator */}
          {ssoDetecting && mode === 'login' && (
            <div className="mt-2 flex items-center gap-2 text-xs text-zinc-500">
              <div className="w-3 h-3 border border-zinc-500/30 border-t-zinc-500 rounded-full animate-spin" />
              Checking for SSO...
            </div>
          )}

          {/* Global SSO Login Options (when no org-specific SSO detected) */}
          {!detectedSSO && ssoProviders.length > 0 && (mode === 'login' || mode === 'register') && (
            <>
              <div className="relative my-4">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-zinc-700" />
                </div>
                <div className="relative flex justify-center text-xs">
                  <span className="bg-zinc-900 px-2 text-zinc-500">or continue with</span>
                </div>
              </div>

              <div className="space-y-2">
                {ssoProviders.map((provider) => (
                  <button
                    key={provider.id}
                    type="button"
                    onClick={() => handleSSOLogin(provider.id)}
                    disabled={ssoLoading !== null}
                    className="w-full flex items-center justify-center gap-3 px-4 py-2.5 bg-zinc-800 border border-zinc-700 text-zinc-200 rounded-md text-sm font-medium hover:bg-zinc-700 hover:border-zinc-600 disabled:opacity-50 transition-colors"
                  >
                    {ssoLoading === provider.id ? (
                      <div className="w-4 h-4 border-2 border-zinc-400/30 border-t-zinc-400 rounded-full animate-spin" />
                    ) : (
                      getProviderIcon(provider.icon)
                    )}
                    <span>
                      {ssoLoading === provider.id ? 'Redirecting...' : `Continue with ${provider.name}`}
                    </span>
                  </button>
                ))}
              </div>
            </>
          )}
        </form>
      </div>
    </div>
  )
}
