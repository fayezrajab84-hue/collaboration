import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Kept in sync with apps/web/src/lib/colors.ts (SEVERITY_CHART)
        // and apps/api/src/services/reportHtmlService.ts (SEV_HEX).
        severity: {
          critical: "#b91c1c",
          high:     "#c2410c",
          medium:   "#a16207",
          low:      "#0369a1",
          info:     "#64748b",
        },
      },
    },
  },
  plugins: [],
} satisfies Config;
