(() => {
    const STORAGE_KEY = 'theme';
    const SYSTEM_THEME_MEDIA = '(prefers-color-scheme: dark)';
    const THEME_PALETTES = {
        light: {
            'accent-color': '#5DADE2',
            'select-color': '#D6EAF8',
            'link-color': '#3498DB',
            'bg-color': '#EBF5FB',
            'text-color': '#2C3E50',
            'bg-color2': '#FFFFFF',
            'border-color': '#85C1E9',
            'post-shadow-color': '#5DADE240',
            'special-text-color': '#1F618D',
            dataset: 'azure-elegance',
        },
        dark: {
            'accent-color': '#6CB4E8',
            'select-color': '#1E3A5F',
            'link-color': '#85C1E9',
            'bg-color': '#0F1C2E',
            'text-color': '#D4E7F5',
            'bg-color2': '#1A2844',
            'border-color': '#2E5984',
            'post-shadow-color': '#00000050',
            'special-text-color': '#A8D0F0',
            dataset: 'midnight-blue-fancy',
        },
    };

    const systemThemeMedia = window.matchMedia(SYSTEM_THEME_MEDIA);

    function getStoredTheme() {
        return localStorage.getItem(STORAGE_KEY) || 'light';
    }

    function resolveTheme(theme) {
        if (theme === 'system') {
            return systemThemeMedia.matches ? 'dark' : 'light';
        }

        return theme === 'dark' ? 'dark' : 'light';
    }

    function applyPalette(root, palette) {
        Object.entries(palette).forEach(([name, value]) => {
            if (name !== 'dataset') {
                root.style.setProperty(`--${name}`, value);
            }
        });
        root.setAttribute('data-theme', palette.dataset);
    }

    function applyTheme(theme) {
        const resolvedTheme = resolveTheme(theme);
        applyPalette(document.documentElement, THEME_PALETTES[resolvedTheme]);
    }

    function handleSystemThemeChange() {
        if (getStoredTheme() === 'system') {
            applyTheme('system');
        }
    }

    applyTheme(getStoredTheme());

    document.addEventListener('DOMContentLoaded', () => {
        const themeSwitcher = document.getElementById('theme-switcher');
        const savedTheme = getStoredTheme();

        if (themeSwitcher) {
            themeSwitcher.value = savedTheme;
            themeSwitcher.addEventListener('change', (event) => {
                const selectedTheme = event.target.value;
                localStorage.setItem(STORAGE_KEY, selectedTheme);
                applyTheme(selectedTheme);
            });
        }

        systemThemeMedia.addEventListener('change', handleSystemThemeChange);
    });
})();
