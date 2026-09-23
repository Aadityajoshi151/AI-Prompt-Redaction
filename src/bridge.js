/*
 * Content-script world. The page script can't use extension storage, so this
 * relays settings to it (and to the on-page indicator), records stats, and
 * forwards redaction events to the indicator.
 */
(function () {
  "use strict";
  const TAG = "__prompt_redaction__";
  const DEFAULTS = { enabled: true, overrides: {}, customTerms: [] };
  // Firefox exposes promise-based `browser`; Chrome's MV3 `chrome` is promise-based too.
  const api = globalThis.browser ?? globalThis.chrome;
  const UI = globalThis.PromptRedactionUI;

  async function pushSettings() {
    const s = await api.storage.sync.get(DEFAULTS);
    window.postMessage({ tag: TAG, type: "settings", settings: s }, location.origin);
    UI.setSettings(s);
  }

  pushSettings();
  api.storage.onChanged.addListener((_, area) => { if (area === "sync") pushSettings(); });

  window.addEventListener("message", (e) => {
    if (e.source !== window || !e.data || e.data.tag !== TAG) return;
    if (e.data.type === "ready") pushSettings();
    if (e.data.type === "redacted") onRedacted(e.data.findings || {}, e.data.matches || []);
  });

  async function onRedacted(findings, matches) {
    UI.onRedacted(findings, matches);
    const { stats = { total: 0 } } = await api.storage.local.get("stats");
    stats.total += matches.length;
    await api.storage.local.set({ stats });
  }
})();
