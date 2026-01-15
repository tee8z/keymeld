// Theme toggle functionality
(function() {
    function updateToggleIcons(isDark) {
        const lightIcon = document.getElementById('theme-icon-light');
        const darkIcon = document.getElementById('theme-icon-dark');
        if (lightIcon && darkIcon) {
            lightIcon.style.display = isDark ? 'none' : 'inline-flex';
            darkIcon.style.display = isDark ? 'inline-flex' : 'none';
        }
    }

    function getCurrentTheme() {
        return document.documentElement.getAttribute('data-theme') ||
               (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    }

    function setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('keymeld-theme', theme);
        updateToggleIcons(theme === 'dark');
    }

    function toggleTheme() {
        const current = getCurrentTheme();
        setTheme(current === 'dark' ? 'light' : 'dark');
    }

    function initThemeToggle() {
        const toggleBtn = document.getElementById('theme-toggle');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', toggleTheme);
            // Update icons to match current theme
            updateToggleIcons(getCurrentTheme() === 'dark');
        }
    }

    // Initialize on page load
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initThemeToggle);
    } else {
        initThemeToggle();
    }

    // Re-initialize after HTMX swaps (for SPA navigation)
    document.addEventListener('htmx:afterSwap', initThemeToggle);
})();
