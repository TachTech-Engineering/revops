import { createSlice, PayloadAction } from '@reduxjs/toolkit'

export type UserRole = 'admin' | 'analyst' | 'viewer'

interface AuthState {
  isAuthenticated: boolean
  pantherHost: string | null
  pantherToken: string | null
  userEmail: string | null
  userRole: UserRole
}

const loadFromStorage = (): AuthState => {
  // Use sessionStorage - clears when browser tab closes for better security
  const stored = sessionStorage.getItem('panther_auth')
  if (stored) {
    try {
      const parsed = JSON.parse(stored)
      return {
        isAuthenticated: true,
        pantherHost: parsed.pantherHost,
        pantherToken: parsed.pantherToken,
        userEmail: parsed.userEmail || null,
        userRole: parsed.userRole || 'viewer',
      }
    } catch {
      return { isAuthenticated: false, pantherHost: null, pantherToken: null, userEmail: null, userRole: 'viewer' }
    }
  }
  return { isAuthenticated: false, pantherHost: null, pantherToken: null, userEmail: null, userRole: 'viewer' }
}

const initialState: AuthState = loadFromStorage()

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    login: (state, action: PayloadAction<{ pantherHost: string; pantherToken: string; userEmail?: string }>) => {
      state.isAuthenticated = true
      state.pantherHost = action.payload.pantherHost
      state.pantherToken = action.payload.pantherToken
      state.userEmail = action.payload.userEmail || null
      sessionStorage.setItem('panther_auth', JSON.stringify({
        pantherHost: action.payload.pantherHost,
        pantherToken: action.payload.pantherToken,
        userEmail: action.payload.userEmail,
        userRole: state.userRole,
      }))
    },
    setUserRole: (state, action: PayloadAction<UserRole>) => {
      state.userRole = action.payload
      const stored = sessionStorage.getItem('panther_auth')
      if (stored) {
        const parsed = JSON.parse(stored)
        sessionStorage.setItem('panther_auth', JSON.stringify({
          ...parsed,
          userRole: action.payload,
        }))
      }
    },
    setUserEmail: (state, action: PayloadAction<string>) => {
      state.userEmail = action.payload
      const stored = sessionStorage.getItem('panther_auth')
      if (stored) {
        const parsed = JSON.parse(stored)
        sessionStorage.setItem('panther_auth', JSON.stringify({
          ...parsed,
          userEmail: action.payload,
        }))
      }
    },
    logout: (state) => {
      state.isAuthenticated = false
      state.pantherHost = null
      state.pantherToken = null
      state.userEmail = null
      state.userRole = 'viewer'
      sessionStorage.removeItem('panther_auth')
    },
  },
})

export const { login, logout, setUserRole, setUserEmail } = authSlice.actions
export default authSlice.reducer
