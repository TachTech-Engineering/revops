import { configureStore } from '@reduxjs/toolkit'
import { setupListeners } from '@reduxjs/toolkit/query'
import { revopsApi } from '../api/pantherApi'
import uiReducer from './uiSlice'
import authReducer from './authSlice'

export const store = configureStore({
  reducer: {
    [revopsApi.reducerPath]: revopsApi.reducer,
    ui: uiReducer,
    auth: authReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware().concat(revopsApi.middleware),
})

setupListeners(store.dispatch)

export type RootState = ReturnType<typeof store.getState>
export type AppDispatch = typeof store.dispatch
