import { createSlice, PayloadAction } from '@reduxjs/toolkit'

export type UserRole = 'admin' | 'analyst' | 'viewer'

interface AuthState {
  isAuthenticated: boolean
  userEmail: string | null
  userName: string | null
  userId: string | null
  organizationId: string | null
  organizationName: string | null
  accessToken: string | null
  refreshToken: string | null
  userRole: UserRole
}

const STORAGE_KEY = 'revops_auth'

interface StoredAuth {
  userEmail: string | null
  userName: string | null
  userId: string | null
  organizationId: string | null
  organizationName: string | null
  accessToken: string | null
  refreshToken: string | null
  userRole: UserRole
}

const unauthenticatedState = (): AuthState => ({
  isAuthenticated: false,
  userEmail: null,
  userName: null,
  userId: null,
  organizationId: null,
  organizationName: null,
  accessToken: null,
  refreshToken: null,
  userRole: 'viewer',
})

// Decode the payload of a JWT (base64url, no signature verification -- we only
// need the public `exp` claim) and return its expiry as seconds since epoch,
// or null if the token is not a decodable JWT with a numeric `exp`.
const getJwtExpiry = (token: string): number | null => {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  try {
    // base64url -> base64, re-pad to a multiple of 4 for atob
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=')
    const payload: unknown = JSON.parse(atob(padded))
    if (payload && typeof payload === 'object' && 'exp' in payload) {
      const exp = (payload as { exp: unknown }).exp
      return typeof exp === 'number' ? exp : null
    }
    return null
  } catch {
    return null
  }
}

// Treat tokens expiring within this window as already expired, so we don't
// boot the app on a token that dies before the first request lands.
const EXPIRY_LEEWAY_MS = 30_000

const loadFromStorage = (): AuthState => {
  const stored = localStorage.getItem(STORAGE_KEY)
  if (stored) {
    try {
      const parsed: StoredAuth = JSON.parse(stored)

      // Expiry check on load. The access token is a JWT with an `exp` claim;
      // the refresh token is an opaque random string (backend mints it with
      // secrets.token_urlsafe), so its validity CANNOT be verified client-side.
      // If the access token is expired (or not a decodable JWT) we therefore
      // start unauthenticated and let the login redirect handle it, rather
      // than optimistically rendering the authenticated shell on a possibly
      // dead session. Mid-session access-token expiry is still handled
      // transparently by the 401 -> /auth/refresh flow in pantherApi.ts.
      const exp = parsed.accessToken ? getJwtExpiry(parsed.accessToken) : null
      if (exp === null || exp * 1000 <= Date.now() + EXPIRY_LEEWAY_MS) {
        localStorage.removeItem(STORAGE_KEY)
        return unauthenticatedState()
      }

      return {
        isAuthenticated: true,
        userEmail: parsed.userEmail || null,
        userName: parsed.userName || null,
        userId: parsed.userId || null,
        organizationId: parsed.organizationId || null,
        organizationName: parsed.organizationName || null,
        accessToken: parsed.accessToken || null,
        refreshToken: parsed.refreshToken || null,
        userRole: parsed.userRole || 'viewer',
      }
    } catch {
      return unauthenticatedState()
    }
  }
  return unauthenticatedState()
}

const saveToStorage = (state: AuthState) => {
  const toStore: StoredAuth = {
    userEmail: state.userEmail,
    userName: state.userName,
    userId: state.userId,
    organizationId: state.organizationId,
    organizationName: state.organizationName,
    accessToken: state.accessToken,
    refreshToken: state.refreshToken,
    userRole: state.userRole,
  }
  localStorage.setItem(STORAGE_KEY, JSON.stringify(toStore))
}

const initialState: AuthState = loadFromStorage()

interface LoginPayload {
  userEmail: string
  userName?: string | null
  userId?: string | null
  organizationId?: string | null
  organizationName?: string | null
  accessToken?: string | null
  refreshToken?: string | null
  userRole?: UserRole
}

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    login: (state, action: PayloadAction<LoginPayload>) => {
      state.isAuthenticated = true
      state.userEmail = action.payload.userEmail
      state.userName = action.payload.userName || null
      state.userId = action.payload.userId || null
      state.organizationId = action.payload.organizationId || null
      state.organizationName = action.payload.organizationName || null
      state.accessToken = action.payload.accessToken || null
      state.refreshToken = action.payload.refreshToken || null
      state.userRole = action.payload.userRole || 'viewer'
      saveToStorage(state)
    },
    setTokens: (state, action: PayloadAction<{ accessToken: string; refreshToken: string }>) => {
      state.accessToken = action.payload.accessToken
      state.refreshToken = action.payload.refreshToken
      saveToStorage(state)
    },
    setUserRole: (state, action: PayloadAction<UserRole>) => {
      state.userRole = action.payload
      saveToStorage(state)
    },
    setUserEmail: (state, action: PayloadAction<string>) => {
      state.userEmail = action.payload
      saveToStorage(state)
    },
    logout: (state) => {
      state.isAuthenticated = false
      state.userEmail = null
      state.userName = null
      state.userId = null
      state.organizationId = null
      state.organizationName = null
      state.accessToken = null
      state.refreshToken = null
      state.userRole = 'viewer'
      localStorage.removeItem(STORAGE_KEY)
    },
  },
})

export const { login, logout, setUserRole, setUserEmail, setTokens } = authSlice.actions
export default authSlice.reducer
