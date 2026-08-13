import { configureStore, createListenerMiddleware } from '@reduxjs/toolkit'
import { setupListeners } from '@reduxjs/toolkit/query'
import { revopsApi } from '../api/pantherApi'
import uiReducer from './uiSlice'
import authReducer, { logout } from './authSlice'

// Ending a session must also wipe the RTK Query cache. Without this the cached
// responses of the previous tenant survive in the store (and are served to the
// next user who signs in on the same browser before their own fetches land),
// which is a cross-tenant data leak. Doing it as a listener -- rather than at
// each `dispatch(logout())` call site -- means every logout path is covered:
// the Layout menu, and the forced logout in pantherApi's 401/refresh handler.
// Dispatching resetApiState (instead of resetting the reducer directly) also
// lets the api middleware abort in-flight requests and drop subscriptions.
const logoutListener = createListenerMiddleware()
logoutListener.startListening({
  actionCreator: logout,
  effect: (_action, listenerApi) => {
    listenerApi.dispatch(revopsApi.util.resetApiState())
  },
})

export const store = configureStore({
  reducer: {
    [revopsApi.reducerPath]: revopsApi.reducer,
    ui: uiReducer,
    auth: authReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware().prepend(logoutListener.middleware).concat(revopsApi.middleware),
})

setupListeners(store.dispatch)

export type RootState = ReturnType<typeof store.getState>
export type AppDispatch = typeof store.dispatch
