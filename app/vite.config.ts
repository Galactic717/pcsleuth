import { defineConfig } from "vitest/config";

// Tauri serves `dist/` itself, so nothing here is a server setting except the dev port.
export default defineConfig({
  base: "./",
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: { target: "chrome110", outDir: "dist", emptyOutDir: true },
  test: { environment: "jsdom", include: ["tests/**/*.test.ts"] },
});
