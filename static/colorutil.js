// colorutil.js — shared color parsing for the WebGL renderers (glrenderer.js
// and cosmosrenderer.js), loaded before both. One implementation, one cache:
// the two renderers previously carried byte-identical copies.
(function () {
    'use strict';

    // Parse '#rgb', '#rrggbb', 'rgb()', 'rgba()' to [r,g,b,a] in 0..1. Cached.
    const colorCache = new Map();
    window.parseRendererColor = function parseRendererColor(str, fallback) {
        if (!str || typeof str !== 'string') return fallback || [0.5, 0.5, 0.5, 1];
        let c = colorCache.get(str);
        if (c) return c.slice();
        let m;
        if (str[0] === '#') {
            const hex = str.slice(1);
            if (hex.length === 3) {
                c = [parseInt(hex[0] + hex[0], 16) / 255, parseInt(hex[1] + hex[1], 16) / 255,
                    parseInt(hex[2] + hex[2], 16) / 255, 1];
            } else {
                c = [parseInt(hex.slice(0, 2), 16) / 255, parseInt(hex.slice(2, 4), 16) / 255,
                    parseInt(hex.slice(4, 6), 16) / 255, 1];
            }
        } else if ((m = str.match(/rgba?\(([^)]+)\)/))) {
            const p = m[1].split(',').map(Number);
            c = [p[0] / 255, p[1] / 255, p[2] / 255, p.length > 3 ? p[3] : 1];
        } else {
            c = fallback || [0.5, 0.5, 0.5, 1];
        }
        colorCache.set(str, c);
        return c.slice();
    };

    // Theme-aware protocol/edge color: server palette is tuned for dark UI;
    // on light theme darken pale colors (e.g. Other #ecf0f1) so links stay visible.
    window.themeProtocolColor = function themeProtocolColor(hex, isLight) {
        const c = window.parseRendererColor(hex, [0.6, 0.65, 0.7, 1]);
        if (!isLight) {
            // Dark mode: slightly boost saturation/brightness for neon link look.
            const max = Math.max(c[0], c[1], c[2]);
            if (max > 0 && max < 0.95) {
                const b = 0.12;
                c[0] = Math.min(1, c[0] + (1 - c[0]) * b);
                c[1] = Math.min(1, c[1] + (1 - c[1]) * b);
                c[2] = Math.min(1, c[2] + (1 - c[2]) * b);
            }
            return c;
        }
        // Light mode: pull very light colors down; keep mid tones readable.
        const lum = 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
        if (lum > 0.75) {
            c[0] *= 0.45; c[1] *= 0.45; c[2] *= 0.45;
        } else if (lum > 0.55) {
            c[0] *= 0.7; c[1] *= 0.7; c[2] *= 0.7;
        }
        return c;
    };

    window.isLightTheme = function isLightTheme() {
        return document.body.classList.contains('light-theme');
    };
})();
