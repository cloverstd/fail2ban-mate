import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwind from "@tailwindcss/vite";
export default defineConfig(({ mode }) => ({
  define: { __ADMIN__: mode === "admin" },
  base: mode === "admin" ? "/admin/" : "/",
  build: {
    outDir: mode === "admin" ? "dist/admin" : "dist",
    copyPublicDir: mode !== "admin",
  },
  plugins: [react(), tailwind()],
  server: {
    proxy: {
      "/api": { target: "http://localhost:8787", ws: true },
      "/install.sh": "http://localhost:8787",
    },
  },
}));
