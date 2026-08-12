import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    rollupOptions: {
      output: {
        // Split heavy libs into their own long-cached chunks so they are not
        // bundled into the entry chunk. Keep the groups coarse to avoid
        // over-fragmentation.
        manualChunks(id) {
          if (!id.includes('node_modules')) return undefined
          if (id.includes('monaco-editor') || id.includes('@monaco-editor')) {
            return 'monaco'
          }
          if (id.includes('reactflow') || id.includes('@reactflow')) {
            return 'reactflow'
          }
          if (
            id.includes('/react/') ||
            id.includes('/react-dom/') ||
            id.includes('/react-router') ||
            id.includes('/scheduler/') ||
            id.includes('/redux') ||
            id.includes('/@reduxjs/') ||
            id.includes('/react-redux/')
          ) {
            return 'vendor-react'
          }
          return undefined
        },
      },
    },
  },
  server: {
    port: 3000,
    host: '0.0.0.0',
    proxy: {
      '/api': {
        target: process.env.API_PROXY_TARGET || 'http://backend:8000',
        changeOrigin: true,
      },
    },
  },
})
