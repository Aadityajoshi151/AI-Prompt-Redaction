/*
 * Content-script world. Holds the settings and does the redaction the page
 * script (interceptor.js) asks for, so detectors and custom terms never enter
 * the page. Also passes settings and redaction events to the on-page indicator
 * and records stats.
 */
(function () {
  "use strict";
  const TAG = "__prompt_redaction__";
  const DEFAULTS = { enabled: true, overrides: {}, customTerms: [] };
  // Firefox exposes promise-based `browser`; Chrome's MV3 `chrome` is promise-based too.
  const api = globalThis.browser ?? globalThis.chrome;
  const R = globalThis.PromptRedaction;
  const UI = globalThis.PromptRedactionUI;
  // Same value -> same placeholder for the whole page session.
  const ctx = R.createContext();

  let settings = DEFAULTS;
  async function loadSettings() {
    try { settings = await api.storage.sync.get(DEFAULTS); }
    catch (err) { console.warn("[AI Prompt Redaction] couldn't read settings, using defaults:", err); }
    UI.setSettings(settings);
  }
  const loaded = loadSettings();
  api.storage.onChanged.addListener((_, area) => { if (area === "sync") loadSettings(); });

  const post = (msg) => window.postMessage(Object.assign({ tag: TAG }, msg), location.origin);

  window.addEventListener("message", async (e) => {
    if (e.source !== window || !e.data || e.data.tag !== TAG) return;
    if (e.data.type === "hello") post({ type: "ready" });
    if (e.data.type === "redact") post({ type: "result", id: e.data.id, texts: await redactAll(e.data.strings) });
  });
  post({ type: "ready" });

  // Redacts each string with the current settings. Returns the new strings,
  // or null when redaction is off or nothing was found.
  async function redactAll(strings) {
    await loaded;
    if (!Array.isArray(strings)) return null;
    strings = strings.map(String);
    const findings = {}, matches = [];
    const texts = !settings.enabled ? strings : strings.map((s) => {
      const res = R.redact(s, { overrides: settings.overrides, customTerms: settings.customTerms, ctx });
      for (const k in res.findings) findings[k] = (findings[k] || 0) + res.findings[k];
      matches.push(...res.matches);
      return res.text;
    });
    // Tell the indicator what is actually leaving the browser, so it can stop
    // marking a value "not sent" once that value goes out unredacted.
    UI.onOutgoing(texts);
    if (!matches.length) return null;
    onRedacted(findings, matches);
    return texts;
  }

  async function onRedacted(findings, matches) {
    UI.onRedacted(findings, matches);
    const { stats = { total: 0 } } = await api.storage.local.get("stats");
    stats.total += matches.length;
    await api.storage.local.set({ stats });
  }
})();
