/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'navy': '#0A0820',
        'wine': '#120D2E',
        'crimson': '#1B1248',
        'blood': '#3A1C77',
        'red': '#FF5BD9',
        'vermil': '#C77BFF',
        'orange': '#2DD96B',
        'amber': '#5BD9FF',
        'gold': '#A0FFD0',
        'yellow': '#FFF066',

        'bg-primary': '#0A0820',
        'bg-secondary': '#100C2B',
        'bg-tertiary': '#181238',
        'bg-quaternary': '#221646',
        'line-primary': '#2A1F58',
        'line-secondary': '#3A2C70',
        'ink-primary': '#ECE6FF',
        'ink-secondary': '#BBB0E8',
        'mute-primary': '#7B7099',
        'mute-secondary': '#544A75',

        'attacker': '#FF5BD9',
        'attacker-secondary': '#C77BFF',
        'attacker-wash': 'rgba(255,91,217,0.10)',

        'decoy': '#2DD96B',
        'decoy-secondary': '#A0FFD0',
        'decoy-wash': 'rgba(45,217,107,0.10)',
      },
      fontFamily: {
        'display': ['"Funnel Display"', 'sans-serif'],
        'sans': ['"Geist"', 'sans-serif'],
        'mono': ['"JetBrains Mono"', 'monospace'],
      }
    },
  },
  plugins: [],
}
