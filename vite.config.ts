import { defineConfig } from "vite";

export default defineConfig({
  root: "client",
  base: "./",
  server: { port: 5174 },
  build: { outDir: "../dist", emptyOutDir: true },
  test: {
    root: ".",
    include: ["tests/**/*.test.ts"],
  },
});
