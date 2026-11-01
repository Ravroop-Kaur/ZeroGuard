import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const target = "http://127.0.0.1:8000";   // FastAPI in dev; build output is served by FastAPI itself
export default defineConfig({
  plugins: [react()],
  build: { outDir: "../backend/static", emptyOutDir: true },
  server: { proxy: Object.fromEntries(["/stats", "/audit", "/policies", "/access-request", "/resources", "/health"].map((p) => [p, target])) },
});
