/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./loby/templates/**/*.{html,js}'],
  plugins: [],
  theme: {
    extend: {
      colors: {
        'primary': '#5e60ce',
        'secondary': '#4ea8de',
        'accent': '#48bfe3',
        'dark': '#1e1e1e',
        'light': '#f4f4f5',
      },
      fontFamily: {
        sans: ['Graphik', 'sans-serif'],
        serif: ['Merriweather', 'serif'],
      },
      container: {
        center: true,
        padding: '2rem',
      },
    },
  },
}

