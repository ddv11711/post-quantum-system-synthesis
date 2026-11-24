/* Shared, purely visual progress indicator for analysis, repair, and XLSX export.
   It does not change network requests, model data, or analysis results. */
(() => {
    'use strict';
    let overlay = null;
    let label = null;

    function ensureOverlay() {
        if (overlay) return;
        overlay = document.createElement('div');
        overlay.className = 'analysis-loading-overlay';
        overlay.hidden = true;
        overlay.setAttribute('role', 'status');
        overlay.setAttribute('aria-live', 'polite');
        overlay.setAttribute('aria-atomic', 'true');
        const panel = document.createElement('div');
        panel.className = 'analysis-loading-panel';
        const ring = document.createElement('span');
        ring.className = 'analysis-loading-ring';
        ring.setAttribute('aria-hidden', 'true');
        label = document.createElement('span');
        label.className = 'analysis-loading-label';
        panel.append(ring, label);
        overlay.append(panel);
        document.body.append(overlay);
    }

    function show(message) {
        ensureOverlay();
        label.textContent = message || 'Выполняем операцию…';
        overlay.hidden = false;
    }

    function hide() {
        if (overlay) overlay.hidden = true;
    }

    // A browser can restore the landing page from the back/forward cache.
    // Never leave its previous navigation overlay visible after returning.
    window.addEventListener('pageshow', (event) => {
        if (event.persisted) hide();
    });
    window.AnalysisLoading = {show, hide};
})();
