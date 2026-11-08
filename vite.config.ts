import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  // GitHub Pages serves a project site from /<repo>/, so every asset URL stays
  // relative: the same build works at /n2f/, on a custom domain, or from disk.
  base: './',
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('/node_modules/@xyflow/') || id.includes('/node_modules/@reactflow/')) {
            return 'reactflow';
          }
          if (
            id.includes('/node_modules/react/') ||
            id.includes('/node_modules/react-dom/') ||
            id.includes('/node_modules/scheduler/')
          ) {
            return 'react';
          }
          if (id.includes('/node_modules/fast-xml-parser/') || id.includes('/node_modules/@xmldom/')) {
            return 'xml-parser';
          }
        },
      },
    },
  },
})
