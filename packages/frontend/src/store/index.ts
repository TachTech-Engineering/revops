import { configureStore } from '@reduxjs/toolkit'
import { setupListeners } from '@reduxjs/toolkit/query'
import { pantherApi } from '../api/pantherApi'
import uiReducer from './uiSlice'
import authReducer from './authSlice'

export const store = configureStore({
  reducer: {
    [pantherApi.reducerPath]: pantherApi.reducer,
    ui: uiReducer,
    auth: authReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware().concat(pantherApi.middleware),
})

setupListeners(store.dispatch)

export type RootState = ReturnType<typeof store.getState>
export type AppDispatch = typeof store.dispatch
