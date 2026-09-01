/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        obsidian: {
          bg: '#0c0e17',
          surface: '#131625',
          card: '#181b2e',
          'card-hover': '#1f233b',
          border: '#242942',
          'border-light': '#32395c',
        },
        neon: {
          blue: '#3b82f6',
          cyan: '#06b6d4',
          sky: '#38bdf8',
          pink: '#f43f5e',
          magenta: '#ec4899',
          purple: '#a855f7',
          violet: '#8b5cf6',
          emerald: '#10b981',
          amber: '#f59e0b',
        }
      },
      borderRadius: {
        '2xl': '1.25rem',
        '3xl': '1.75rem',
        '4xl': '2.25rem',
      },
      boxShadow: {
        'glow-blue': '0 0 25px -5px rgba(59, 130, 246, 0.5)',
        'glow-purple': '0 0 25px -5px rgba(168, 85, 247, 0.5)',
        'glow-pink': '0 0 25px -5px rgba(244, 63, 94, 0.5)',
        'glow-cyan': '0 0 25px -5px rgba(6, 182, 212, 0.5)',
        'dock': '0 10px 30px -5px rgba(0, 0, 0, 0.8), 0 0 20px rgba(168, 85, 247, 0.15)',
        'card-soft': '0 8px 24px -6px rgba(0, 0, 0, 0.6)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'float': 'float 4s ease-in-out infinite',
      },
      keyframes: {
        float: {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-6px)' },
        }
      }
    },
  },
  plugins: [],
}
