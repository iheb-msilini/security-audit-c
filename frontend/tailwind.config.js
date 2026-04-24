/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,jsx}",
    "./components/**/*.{js,jsx}",
  ],
  theme: {
    extend: {
      colors: {
        bg: "#0f172a",
        card: "#1e293b",
        side: "#020617",
        text: "#e2e8f0",
        success: "#22c55e",
        danger: "#ef4444",
        warning: "#f59e0b",
      },
      boxShadow: {
        soft: "0 10px 25px rgba(0,0,0,0.3)",
      },
    },
  },
  plugins: [],
};
