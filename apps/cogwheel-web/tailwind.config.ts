import type { Config } from "tailwindcss";

export default {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
  	extend: {
  		colors: {
  			border: 'hsl(var(--border))',
  			input: 'hsl(var(--input))',
  			ring: 'hsl(var(--ring))',
  			background: 'hsl(var(--background))',
  			foreground: 'hsl(var(--foreground))',
  			primary: {
  				DEFAULT: 'hsl(var(--primary))',
  				foreground: 'hsl(var(--primary-foreground))'
  			},
  			secondary: {
  				DEFAULT: 'hsl(var(--secondary))',
  				foreground: 'hsl(var(--secondary-foreground))'
  			},
  			muted: {
  				DEFAULT: 'hsl(var(--muted))',
  				foreground: 'hsl(var(--muted-foreground))'
  			},
  			accent: {
  				DEFAULT: 'hsl(var(--accent))',
  				foreground: 'hsl(var(--accent-foreground))'
  			},
  			destructive: {
  				DEFAULT: 'hsl(var(--destructive))',
  				foreground: 'hsl(var(--destructive-foreground))'
  			},
  			popover: {
  				DEFAULT: 'hsl(var(--popover))',
  				foreground: 'hsl(var(--popover-foreground))'
  			},
  			card: {
  				DEFAULT: 'hsl(var(--card))',
  				foreground: 'hsl(var(--card-foreground))'
  			},
  			sidebar: {
  				DEFAULT: 'hsl(var(--sidebar-background))',
  				foreground: 'hsl(var(--sidebar-foreground))',
  				primary: 'hsl(var(--sidebar-primary))',
  				'primary-foreground': 'hsl(var(--sidebar-primary-foreground))',
  				accent: 'hsl(var(--sidebar-accent))',
  				'accent-foreground': 'hsl(var(--sidebar-accent-foreground))',
  				border: 'hsl(var(--sidebar-border))',
  				ring: 'hsl(var(--sidebar-ring))',
  				'primary-foreground': 'hsl(var(--sidebar-primary-foreground))',
  				'accent-foreground': 'hsl(var(--sidebar-accent-foreground))'
  			}
  		},
  		fontFamily: {
  			sans: ['DM Sans', 'system-ui', 'sans-serif'],
  			display: ['Instrument Serif', 'Georgia', 'serif'],
  			mono: ['JetBrains Mono', 'monospace'],
  		},
  		borderRadius: {
  			sm: 'calc(var(--radius) * 0.6)',
  			md: 'calc(var(--radius) * 0.8)',
  			lg: 'var(--radius)',
  			xl: 'calc(var(--radius) * 1.4)',
  			'2xl': 'calc(var(--radius) * 1.8)',
  			'3xl': 'calc(var(--radius) * 2.2)',
  			'4xl': 'calc(var(--radius) * 2.6)',
  			full: '9999px',
  		},
  		keyframes: {
  			'accordion-down': {
  				from: {
  					height: '0'
  				},
  				to: {
  					height: 'var(--radix-accordion-content-height)'
  				}
  			},
  			'accordion-up': {
  				from: {
  					height: 'var(--radix-accordion-content-height)'
  				},
  				to: {
  					height: '0'
  				}
  			},
  			'dialog-in': {
  				from: {
  					opacity: '0',
  					transform: 'translate(-50%, -48%) scale(0.96)'
  				},
  				to: {
  					opacity: '1',
  					transform: 'translate(-50%, -50%) scale(1)'
  				}
  			},
  			'dialog-out': {
  				from: {
  					opacity: '1',
  					transform: 'translate(-50%, -50%) scale(1)'
  				},
  				to: {
  					opacity: '0',
  					transform: 'translate(-50%, -48%) scale(0.96)'
  				}
  			},
  			'fade-in': {
  				from: {
  					opacity: '0'
  				},
  				to: {
  					opacity: '1'
  				}
  			},
  			'fade-out': {
  				from: {
  					opacity: '1'
  				},
  				to: {
  					opacity: '0'
  				}
  			},
  			'sheet-in-right': {
  				from: {
  					transform: 'translateX(100%)'
  				},
  				to: {
  					transform: 'translateX(0)'
  				}
  			},
  			'sheet-out-right': {
  				from: {
  					transform: 'translateX(0)'
  				},
  				to: {
  					transform: 'translateX(100%)'
  				}
  			},
  			'sheet-in-left': {
  				from: {
  					transform: 'translateX(-100%)'
  				},
  				to: {
  					transform: 'translateX(0)'
  				}
  			},
  			'sheet-out-left': {
  				from: {
  					transform: 'translateX(0)'
  				},
  				to: {
  					transform: 'translateX(-100%)'
  				}
  			},
  			'sheet-in-top': {
  				from: {
  					transform: 'translateY(-100%)'
  				},
  				to: {
  					transform: 'translateY(0)'
  				}
  			},
  			'sheet-out-top': {
  				from: {
  					transform: 'translateY(0)'
  				},
  				to: {
  					transform: 'translateY(-100%)'
  				}
  			},
  			'sheet-in-bottom': {
  				from: {
  					transform: 'translateY(100%)'
  				},
  				to: {
  					transform: 'translateY(0)'
  				}
  			},
  			'sheet-out-bottom': {
  				from: {
  					transform: 'translateY(0)'
  				},
  				to: {
  					transform: 'translateY(100%)'
  				}
  			}
  		},
  		animation: {
  			'accordion-down': 'accordion-down 0.2s ease-out',
  			'accordion-up': 'accordion-up 0.2s ease-out',
  			'dialog-in': 'dialog-in 0.2s ease-out',
  			'dialog-out': 'dialog-out 0.15s ease-in',
  			'fade-in': 'fade-in 0.2s ease-out',
  			'fade-out': 'fade-out 0.15s ease-in',
  			'sheet-in-right': 'sheet-in-right 0.3s ease-out',
  			'sheet-out-right': 'sheet-out-right 0.2s ease-in',
  			'sheet-in-left': 'sheet-in-left 0.3s ease-out',
  			'sheet-out-left': 'sheet-out-left 0.2s ease-in',
  			'sheet-in-top': 'sheet-in-top 0.3s ease-out',
  			'sheet-out-top': 'sheet-out-top 0.2s ease-in',
  			'sheet-in-bottom': 'sheet-in-bottom 0.3s ease-out',
  			'sheet-out-bottom': 'sheet-out-bottom 0.2s ease-in'
  		}
  	}
  },
  plugins: [],
} satisfies Config;
