/*
 * Runs in the page's MAIN world at document_start, before claude.ai's own code,
 * so every call to fetch() goes through this wrapper. Outgoing JSON bodies sent
 * to claude.ai's API have their user-text fields redacted before the request
 * leaves the browser.
 *
 * The detectors and settings live in the content script (bridge.js), not here:
 * Chromium injects a file only once even when two content_scripts entries list
 * it, and keeping custom terms out of the page means claude.ai's scripts can't
 * read them. This wrapper sends the text fields over postMessage and waits for
 * the redacted text.
 */
(function () {
  "use strict";
  const TAG = "__prompt_redaction__";
  if (window.fetch.__promptRedaction) return;

  // Fields that carry user-written content: the message itself, pasted text
  // attachments, and text added to projects.
  const TEXT_KEYS = new Set(["prompt", "extracted_content", "text", "content"]);
  // How long to wait for the content script before sending unredacted
  // (fail-open), e.g. just after the extension was reloaded.
  const TIMEOUT_MS = 3000;

  let markReady;
  const ready = new Promise((r) => (markReady = r));
  const pending = new Map(); // request id -> resolve(texts)

  window.addEventListener("message", (e) => {
    if (e.source !== window || !e.data || e.data.tag !== TAG) return;
    if (e.data.type === "ready") markReady();
    if (e.data.type === "result" && pending.has(e.data.id)) pending.get(e.data.id)(e.data.texts);
  });
  // If the content script started first, its "ready" went out before this
  // listener existed; "hello" asks it to say so again.
  window.postMessage({ tag: TAG, type: "hello" }, location.origin);

  // Resolves to the redacted strings, or null when nothing changed or
  // redaction is off. Rejects if the content script doesn't answer in time.
  function redactStrings(strings) {
    return new Promise((resolve, reject) => {
      const id = Math.random().toString(36).slice(2) + Date.now().toString(36);
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error("no answer from the extension's content script"));
      }, TIMEOUT_MS);
      pending.set(id, (texts) => {
        clearTimeout(timer);
        pending.delete(id);
        resolve(Array.isArray(texts) && texts.length === strings.length ? texts : null);
      });
      ready.then(() => window.postMessage({ tag: TAG, type: "redact", id, strings }, location.origin));
    });
  }

  // Every string under a TEXT_KEYS key, as [object, key] pairs.
  function collect(node, out) {
    if (Array.isArray(node)) {
      for (const v of node) if (typeof v === "object" && v !== null) collect(v, out);
      return out;
    }
    for (const key of Object.keys(node)) {
      const val = node[key];
      if (typeof val === "string" && TEXT_KEYS.has(key)) out.push([node, key]);
      else if (typeof val === "object" && val !== null) collect(val, out);
    }
    return out;
  }

  // Returns the new body string, or null if nothing changed.
  async function redactBody(body) {
    if (typeof body !== "string" || body[0] !== "{" && body[0] !== "[") return null;
    let data;
    try { data = JSON.parse(body); } catch (_) { return null; }
    const fields = collect(data, []);
    if (!fields.length) return null;
    const texts = await redactStrings(fields.map(([obj, key]) => obj[key]));
    if (!texts) return null;
    fields.forEach(([obj, key], i) => { obj[key] = texts[i]; });
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
      const isReq = input instanceof Request;
      const url = isReq ? input.url : String(input);
      const method = (init && init.method) || (isReq ? input.method : "GET");

      if (isTarget(url, method)) {
        if (init && init.body !== undefined) {
          const newBody = await redactBody(init.body);
          if (newBody !== null) init = Object.assign({}, init, { body: newBody });
        } else if (isReq) {
          const text = await input.clone().text();
          const newBody = await redactBody(text);
          if (newBody !== null) input = new Request(input, { body: newBody });
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
