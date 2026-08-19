import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const allowedReviewHost = process.env.VITE_ALLOWED_HOST;

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5186,
    allowedHosts: allowedReviewHost ? [allowedReviewHost] : [],
    proxy: {
      "/api": "http://127.0.0.1:4700"
    }
  },
  preview: { port: 5186 }
});
