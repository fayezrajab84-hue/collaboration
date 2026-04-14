import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        severity: {
          critical: "#dc2626",
          high: "#ea580c",
          medium: "#d97706",
          low: "#65a30d",
          info: "#6b7280",
        },
      },
    },
  },
  plugins: [],
} satisfies Config;
