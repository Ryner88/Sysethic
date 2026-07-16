(function () {
  'use strict';

  const source = window.SYSETHIC_VOCABULARY || { severities: {}, statuses: {} };

  function key(value) {
    return String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  }

  function normalize(value, vocabulary, fallback) {
    const candidate = key(value);
    for (const [canonical, config] of Object.entries(vocabulary)) {
      if (canonical === candidate || (config.aliases || []).includes(candidate)) return canonical;
    }
    return fallback;
  }

  function config(value, vocabulary, fallback) {
    const normalized = normalize(value, vocabulary, fallback);
    return { value: normalized, ...(vocabulary[normalized] || {}) };
  }

  window.SysEthicVocabulary = {
    normalizeSeverity(value, fallback = 'info') {
      return normalize(value, source.severities, fallback);
    },
    normalizeStatus(value, fallback = 'open') {
      return normalize(value, source.statuses, fallback);
    },
    severity(value) {
      return config(value, source.severities, 'info');
    },
    status(value) {
      return config(value, source.statuses, 'open');
    },
    risk(score) {
      const value = Number(score);
      const severity = !Number.isFinite(value) || value <= 0 ? 'info'
        : value >= 80 ? 'critical'
          : value >= 55 ? 'high'
            : value >= 30 ? 'medium' : 'low';
      return this.severity(severity);
    },
    severityBadge(value) {
      const item = this.severity(value);
      return `<span class="vocabulary-badge ${item.css_class}">${item.label}</span>`;
    },
    statusBadge(value) {
      const item = this.status(value);
      return `<span class="vocabulary-badge ${item.css_class}">${item.label}</span>`;
    }
  };
}());
