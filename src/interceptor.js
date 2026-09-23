/*
 * Runs in the page's MAIN world at document_start, before claude.ai's own code,
 * so every call to fetch() goes through this wrapper. Outgoing JSON bodies sent
 * to claude.ai's API have their user-text fields redacted before the request
 * leaves the browser.
 */
(function () {
  "use strict";
  const TAG = "__prompt_redaction__";
  const R = window.PromptRedaction;
  if (!R || window.fetch.__promptRedaction) return;

  // Fields that carry user-written content: the message itself, pasted text
  // attachments, and text added to projects.
  const TEXT_KEYS = new Set(["prompt", "extracted_content", "text", "content"]);

  let settings = { enabled: true, overrides: {}, customTerms: [] };
  const ctx = R.createContext();

  window.addEventListener("message", (e) => {
    if (e.source !== window || !e.data || e.data.tag !== TAG) return;
    if (e.data.type === "settings" && e.data.settings) settings = e.data.settings;
  });
  window.postMessage({ tag: TAG, type: "ready" }, location.origin);

  function merge(acc, res) {
    for (const k in res.findings) acc.findings[k] = (acc.findings[k] || 0) + res.findings[k];
    acc.matches.push(...res.matches);
  }

  function walk(node, acc) {
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) {
        if (typeof node[i] === "object" && node[i] !== null) walk(node[i], acc);
      }
      return;
    }
    for (const key of Object.keys(node)) {
      const val = node[key];
      if (typeof val === "string" && TEXT_KEYS.has(key)) {
        const res = R.redact(val, { overrides: settings.overrides, customTerms: settings.customTerms, ctx });
        node[key] = res.text;
        merge(acc, res);
      } else if (typeof val === "object" && val !== null) {
        walk(val, acc);
      }
    }
  }

  // Returns the new body string, or null if nothing changed.
  function redactBody(body) {
    if (typeof body !== "string" || body[0] !== "{" && body[0] !== "[") return null;
    let data;
    try { data = JSON.parse(body); } catch (_) { return null; }
    const acc = { findings: {}, matches: [] };
    walk(data, acc);
    if (!acc.matches.length) return null;
    // The content script uses the original values to mark them on the page.
    window.postMessage({ tag: TAG, type: "redacted", findings: acc.findings, matches: acc.matches }, location.origin);
    return JSON.stringify(data);
  }

  function isTarget(url, method) {
    if (!/^(POST|PUT|PATCH)$/i.test(method || "GET")) return false;
    try {
      const u = new URL(url, location.href);
      return u.origin === location.origin && u.pathname.startsWith("/api/");
    } catch (_) { return false; }
  }

  const origFetch = window.fetch;

  async function redactingFetch(input, init) {
    try {
      if (settings.enabled) {
        const isReq = input instanceof Request;
        const url = isReq ? input.url : String(input);
        const method = (init && init.method) || (isReq ? input.method : "GET");

        if (isTarget(url, method)) {
          if (init && init.body !== undefined) {
            const newBody = redactBody(init.body);
            if (newBody !== null) init = Object.assign({}, init, { body: newBody });
          } else if (isReq) {
            const text = await input.clone().text();
            const newBody = redactBody(text);
            if (newBody !== null) input = new Request(input, { body: newBody });
          }
        }
      }
    } catch (err) {
      console.warn("[AI Prompt Redaction] redaction failed, request sent unchanged:", err);
    }
    return origFetch.call(this, input, init);
  }
  redactingFetch.__promptRedaction = true;
  window.fetch = redactingFetch;
})();
