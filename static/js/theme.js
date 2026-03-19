/**
 * Theme Toggle System
 * v5.1 Advanced HTML Reports
 */

(function() {
    'use strict';
    
    // Theme management
    const THEME_KEY = 'mcp-soc-theme';
    
    function getTheme() {
        return localStorage.getItem(THEME_KEY) || 'dark';
    }
    
    function setTheme(theme) {
        localStorage.setItem(THEME_KEY, theme);
        document.documentElement.setAttribute('data-theme', theme);
        updateThemeIcon(theme);
        
        // Update Chart.js if available
        if (window.Chart) {
            updateChartTheme(theme);
        }
    }
    
    function updateThemeIcon(theme) {
        const icon = document.querySelector('.theme-toggle');
        if (icon) {
            icon.textContent = theme === 'dark' ? '☀️' : '🌙';
            icon.title = theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode';
        }
    }
    
    function updateChartTheme(theme) {
        const isDark = theme === 'dark';
        
        // Update Chart.js defaults
        Chart.defaults.color = isDark ? '#e9ecef' : '#212529';
        Chart.defaults.borderColor = isDark ? '#495057' : '#dee2e6';
        
        if (Chart.defaults.plugins && Chart.defaults.plugins.legend) {
            Chart.defaults.plugins.legend.labels.color = isDark ? '#e9ecef' : '#212529';
        }
        
        // Update all existing charts
        Object.values(Chart.instances).forEach(chart => {
            if (chart.options.scales) {
                Object.values(chart.options.scales).forEach(scale => {
                    if (scale.ticks) {
                        scale.ticks.color = isDark ? '#e9ecef' : '#212529';
                    }
                    if (scale.grid) {
                        scale.grid.color = isDark ? '#495057' : '#e9ecef';
                    }
                });
            }
            chart.update();
        });
    }
    
    function toggleTheme() {
        const currentTheme = getTheme();
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        setTheme(newTheme);
    }
    
    // Initialize theme on page load
    function initTheme() {
        const theme = getTheme();
        setTheme(theme);
    }
    
    // Auto-detect system preference
    function detectSystemTheme() {
        if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            return 'dark';
        }
        return 'light';
    }
    
    // Listen for system theme changes
    if (window.matchMedia) {
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
            const newTheme = e.matches ? 'dark' : 'light';
            // Only auto-switch if user hasn't manually set preference
            if (!localStorage.getItem(THEME_KEY)) {
                setTheme(newTheme);
            }
        });
    }
    
    // Keyboard shortcut (Ctrl/Cmd + Shift + T)
    document.addEventListener('keydown', function(e) {
        if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'T') {
            e.preventDefault();
            toggleTheme();
        }
    });
    
    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initTheme);
    } else {
        initTheme();
    }
    
    // Export functions
    window.MCPTheme = {
        toggle: toggleTheme,
        set: setTheme,
        get: getTheme
    };
    
})();
