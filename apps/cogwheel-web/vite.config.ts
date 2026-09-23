import path from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    rollupOptions: {
      output: {
        // The appliance serves these off local disk, but splitting the two big
        // vendor trees means a UI update does not invalidate React or Ark in
        // the browser cache.
        manualChunks(id) {
          if (!id.includes("node_modules")) return undefined;
          if (/node_modules\/(react|react-dom|scheduler)\//.test(id)) return "vendor-react";
          if (/node_modules\/(@ark-ui|@zag-js)\//.test(id)) return "vendor-ark";
          if (/node_modules\/(react-router|react-router-dom|@remix-run)\//.test(id)) {
            return "vendor-router";
          }
          if (id.includes("node_modules/lucide-react")) return "vendor-icons";
          return undefined;
        },
      },
    },
  },
  server: {
    port: 5174,
    // The old app had no proxy, so `npm run dev` 404'd every request unless
    // VITE_COGWHEEL_API_BASE was set. Proxying keeps same-origin semantics in
    // dev identical to production, where the Rust server serves dist/.
    //
    // The default is :30080 because that is what the documented development
    // command binds -- `COGWHEEL_PROFILE=dev cargo run -p cogwheel-server`
    // listens on 127.0.0.1:30080 (apps/cogwheel-server/src/config.rs). This used to
    // point at :8080, the CONTAINER's port, so following docs/DEPLOYMENT.md section
    // 13 gave a dev server on one port and a proxy aimed at another, and every
    // API call in `npm run dev` 404'd -- the exact failure the proxy was added
    // to prevent.
    //
    // Override when pointing the dev UI at a real appliance:
    //   VITE_COGWHEEL_API_TARGET=http://cogwheel.local:8080 npm run dev
    proxy: {
      "/api": {
        target: process.env.VITE_COGWHEEL_API_TARGET ?? "http://127.0.0.1:30080",
        changeOrigin: true,
      },
    },
  },
});
