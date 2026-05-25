import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  // /RetailShield/ base path for GitHub Pages — '/' in local dev
  base: process.env.GITHUB_ACTIONS ? '/RetailShield/' : '/',
  server: {
    port: 5173,
    open: true,
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
})
