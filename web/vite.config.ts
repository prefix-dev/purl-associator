import { resolve } from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `base` is set to "./" so the bundle works whether the site is served
// from the root or from a /repo-name/ subpath (GitHub Pages user/project).
//
// Multi-page: two HTML entries — the PURL mapper at `/` and the CVE
// dashboard at `/cve.html`. Both ship from the same Vite bundle and share
// the auth / Primitives / github helpers under `src/`.
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
      },
    },
  },
});
