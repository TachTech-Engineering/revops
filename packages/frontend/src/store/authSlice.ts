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

const loadFromStorage = (): AuthState => {
  const stored = localStorage.getItem(STORAGE_KEY)
  if (stored) {
    try {
      const parsed: StoredAuth = JSON.parse(stored)
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
      return {
        isAuthenticated: false,
        userEmail: null,
        userName: null,
        userId: null,
        organizationId: null,
        organizationName: null,
        accessToken: null,
        refreshToken: null,
        userRole: 'viewer',
      }
    }
  }
  return {
    isAuthenticated: false,
    userEmail: null,
    userName: null,
    userId: null,
    organizationId: null,
    organizationName: null,
    accessToken: null,
    refreshToken: null,
    userRole: 'viewer',
  }
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
