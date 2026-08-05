/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: '#080B11',
        panel: '#101620',
        line: '#263142',
        signal: '#C9F27A',
        cyan: '#75D6FF',
        ember: '#FF8A65',
      },
      boxShadow: {
        lift: '0 24px 70px rgba(0, 0, 0, 0.34)',
        signal: '0 0 32px rgba(201, 242, 122, 0.18)',
      },
      keyframes: {
        sweep: {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
        pulseSoft: {
          '0%, 100%': { opacity: '0.45' },
          '50%': { opacity: '1' },
        },
      },
      animation: {
        sweep: 'sweep 8s linear infinite',
        'pulse-soft': 'pulseSoft 2.6s ease-in-out infinite',
      },
    },
  },
  plugins: [],
}
