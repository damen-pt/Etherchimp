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
        if (c) return c;
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
        return c;
    };
})();
