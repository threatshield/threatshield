/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          DEFAULT: '#3b82f6',
          dark: '#2563eb',
        },
        secondary: '#64748b',
        background: '#f8fafc',
      },
      animation: {
        'ping-slow': 'ping 3s cubic-bezier(0, 0, 0.2, 1) infinite',
        'blob': 'blob 7s infinite',
        'matrix-fall': 'matrix-fall 10s linear infinite',
        'matrix-fade': 'matrix-fade 2s linear infinite',
      },
      keyframes: {
        blob: {
          '0%': {
            transform: 'translate(0px, 0px) scale(1)',
          },
          '33%': {
            transform: 'translate(30px, -50px) scale(1.1)',
          },
          '66%': {
            transform: 'translate(-20px, 20px) scale(0.9)',
          },
          '100%': {
            transform: 'translate(0px, 0px) scale(1)',
          },
        },
        'matrix-fall': {
          '0%': {
            transform: 'translateY(-100%)',
          },
          '100%': {
            transform: 'translateY(100vh)',
          },
        },
        'matrix-fade': {
          '0%, 100%': {
            opacity: '0',
          },
          '50%': {
            opacity: '1',
          },
        },
      },
    },
  },
  plugins: [],
}
