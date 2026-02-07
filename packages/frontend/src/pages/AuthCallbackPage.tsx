import { useEffect, useState } from 'react'
import { useDispatch } from 'react-redux'
import { useNavigate } from 'react-router-dom'
import { login } from '../store/authSlice'
import RevOpsLogo from '../components/common/RevOpsLogo'

const API_BASE = import.meta.env.VITE_API_BASE_URL || ''

interface UserResponse {
  id: string
  email: string
  name: string | null
  role: string
  is_active: boolean
  organization_id: string | null
  organization_name: string | null
}

export default function AuthCallbackPage() {
  const dispatch = useDispatch()
  const navigate = useNavigate()
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const handleCallback = async () => {
      // Get tokens from URL fragment (hash)
      const hash = window.location.hash.substring(1) // Remove the #
      const params = new URLSearchParams(hash)

      const accessToken = params.get('access_token')
      const refreshToken = params.get('refresh_token')

      if (!accessToken || !refreshToken) {
        setError('Authentication failed. No tokens received.')
        return
      }

      try {
        // Fetch user info with the access token
        const response = await fetch(`${API_BASE}/api/v1/auth/me`, {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        })

        if (!response.ok) {
          throw new Error('Failed to fetch user info')
        }

        const userInfo: UserResponse = await response.json()

        // Store auth state
        dispatch(
          login({
            userEmail: userInfo.email,
            userName: userInfo.name,
            userId: userInfo.id,
            organizationId: userInfo.organization_id,
            organizationName: userInfo.organization_name,
            accessToken,
            refreshToken,
            userRole: (userInfo.role as 'admin' | 'analyst' | 'viewer') || 'viewer',
          })
        )

        // Clear the URL fragment and redirect to home
        window.history.replaceState(null, '', window.location.pathname)
        navigate('/')
      } catch (err) {
        console.error('Auth callback error:', err)
        setError('Authentication failed. Please try again.')
      }
    }

    handleCallback()
  }, [dispatch, navigate])

  if (error) {
    return (
      <div className="dark min-h-screen bg-zinc-950 flex items-center justify-center p-4">
        <div className="w-full max-w-md text-center">
          <div className="inline-flex items-center justify-center mb-4">
            <RevOpsLogo size={64} />
          </div>
          <div className="rounded-lg border border-red-500/20 bg-red-500/10 p-6">
            <h2 className="text-lg font-semibold text-red-400 mb-2">Authentication Failed</h2>
            <p className="text-zinc-400 mb-4">{error}</p>
            <button
              onClick={() => navigate('/login')}
              className="px-4 py-2 bg-blue-600 text-white rounded-md text-sm font-medium hover:bg-blue-700 transition-colors"
            >
              Back to Login
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="dark min-h-screen bg-zinc-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md text-center">
        <div className="inline-flex items-center justify-center mb-4">
          <RevOpsLogo size={64} />
        </div>
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
          <div className="flex items-center justify-center gap-3">
            <div className="w-5 h-5 border-2 border-blue-400/30 border-t-blue-400 rounded-full animate-spin" />
            <span className="text-zinc-300">Completing sign in...</span>
          </div>
        </div>
      </div>
    </div>
  )
}
