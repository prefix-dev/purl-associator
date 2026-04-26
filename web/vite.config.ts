import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `base` is set to "./" so the bundle works whether the site is served
// from the root or from a /repo-name/ subpath (GitHub Pages user/project).
export default defineConfig({
  plugins: [react()],
  base: "./",
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
