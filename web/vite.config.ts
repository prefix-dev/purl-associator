import { resolve } from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `base` is set to "./" so the bundle works whether the site is served
// from the root or from a /repo-name/ subpath (GitHub Pages user/project).
//
// Multi-page entries share auth / primitives / github helpers under `src/`.
export default defineConfig({
  plugins: [react()],
  base: "./",
  build: {
    outDir: "dist",
    sourcemap: true,
    rollupOptions: {
      input: {
        main: resolve(__dirname, "index.html"),
        cve: resolve(__dirname, "cve.html"),
        deep: resolve(__dirname, "deep.html"),
      },
    },
  },
});
