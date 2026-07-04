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
          50: "#eef7ff",
          100: "#d9ecff",
          500: "#1d4ed8",
          600: "#1e40af",
          700: "#1e3a8a",
          900: "#0f172a"
        }
      }
    },
  },
  plugins: [],
}
