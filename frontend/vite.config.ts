import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

export default defineConfig({
  plugins: [react()],
  root: path.resolve(__dirname, "src"),
  build: {
    outDir: path.resolve(__dirname, "../Suspicious/Suspicious/tasp/static/vite"),
    emptyOutDir: true,
    manifest: true,
    rollupOptions: {
      input: {
        dashboard: path.resolve(__dirname, "src/dashboard.tsx"),
        main: path.resolve(__dirname, "src/main.tsx")
      }
    }
  }
});
