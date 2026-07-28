/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: "class",
  content: [
    "./app/**/*.py",
    "./app/static/css/tailwind.css",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: [
          "\"IBM Plex Sans\"",
          "\"Segoe UI Variable Text\"",
          "\"Segoe UI\"",
          "ui-sans-serif",
          "system-ui",
          "sans-serif",
        ],
        mono: [
          "\"Cascadia Code\"",
          "\"SFMono-Regular\"",
          "Consolas",
          "monospace",
        ],
      },
      boxShadow: {
        shell: "0 24px 80px rgba(15, 23, 42, 0.10)",
        card: "0 14px 42px rgba(15, 23, 42, 0.08)",
      },
      borderRadius: {
        xl2: "1rem",
      },
      colors: {
        masp: {
          50: "#f0f9ff",
          100: "#e0f2fe",
          500: "#0ea5e9",
          600: "#0284c7",
          700: "#0369a1",
          900: "#0c4a6e"
        }
      }
    },
  },
  plugins: [],
}
