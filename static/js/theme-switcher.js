(function() {
    function applyTheme(theme) {
        const root = document.documentElement;
        
        if (theme === 'system') {
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            if (prefersDark) {
                setDarkTheme(root);
                root.setAttribute('data-theme', 'midnight-blue-fancy');
            } else {
                setLightTheme(root);
                root.setAttribute('data-theme', 'azure-elegance');
            }
        } else if (theme === 'dark') {
            setDarkTheme(root);
            root.setAttribute('data-theme', 'midnight-blue-fancy');
        } else {
            setLightTheme(root);
            root.setAttribute('data-theme', 'azure-elegance');
        }
    }
    
    function setLightTheme(root) {
        root.style.setProperty('--accent-color', '#5DADE2');
        root.style.setProperty('--select-color', '#D6EAF8');
        root.style.setProperty('--link-color', '#3498DB');
        root.style.setProperty('--bg-color', '#EBF5FB');
        root.style.setProperty('--text-color', '#2C3E50');
        root.style.setProperty('--bg-color2', '#FFFFFF');
        root.style.setProperty('--border-color', '#85C1E9');
        root.style.setProperty('--post-shadow-color', '#5DADE240');
        root.style.setProperty('--special-text-color', '#1F618D');
    }
    
    function setDarkTheme(root) {
        root.style.setProperty('--accent-color', '#6CB4E8');
        root.style.setProperty('--select-color', '#1E3A5F');
        root.style.setProperty('--link-color', '#85C1E9');
        root.style.setProperty('--bg-color', '#0F1C2E');
        root.style.setProperty('--text-color', '#D4E7F5');
        root.style.setProperty('--bg-color2', '#1A2844');
        root.style.setProperty('--border-color', '#2E5984');
        root.style.setProperty('--post-shadow-color', '#00000050');
        root.style.setProperty('--special-text-color', '#A8D0F0');
    }
    
    const savedTheme = localStorage.getItem('theme') || 'light';
    applyTheme(savedTheme);
    
    document.addEventListener('DOMContentLoaded', function() {
        const themeSwitcher = document.getElementById('theme-switcher');
        
        if (themeSwitcher) {
            themeSwitcher.value = savedTheme;
            
            themeSwitcher.addEventListener('change', function() {
                const theme = this.value;
                localStorage.setItem('theme', theme);
                applyTheme(theme);
            });
        }
        
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function() {
            if (localStorage.getItem('theme') === 'system') {
                applyTheme('system');
            }
        });
    });
})();
