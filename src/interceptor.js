/*
 * Runs in the page's MAIN world at document_start, before claude.ai's own code,
 * so every fetch() and XMLHttpRequest goes through these wrappers. Outgoing JSON
 * bodies sent to claude.ai's API have their user-text fields redacted before
 * the request leaves the browser, including gzip-compressed bodies (claude.ai
 * compresses larger requests, e.g. messages with text attachments).
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

  // Bodies arrive as text, bytes, Blobs or streams. Returns { text, gzip, raw }
  // (raw: the original bytes, when reading used the body up), or null when the
  // body isn't something we can read as JSON (FormData, URLSearchParams).
  async function readBody(body) {
    if (typeof body === "string") return { text: body, gzip: false, raw: null };
    let bytes, raw = null;
    if (ArrayBuffer.isView(body)) bytes = new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    else if (Object.prototype.toString.call(body) === "[object ArrayBuffer]") bytes = new Uint8Array(body);
    else if (typeof Blob === "function" && body instanceof Blob) bytes = new Uint8Array(await body.arrayBuffer());
    else if (typeof ReadableStream === "function" && body instanceof ReadableStream) {
      bytes = raw = new Uint8Array(await new Response(body).arrayBuffer());
    } else return null;
    const gzip = bytes[0] === 0x1f && bytes[1] === 0x8b;
    if (gzip) bytes = await pipe(bytes, new DecompressionStream("gzip"));
    return { text: new TextDecoder().decode(bytes), gzip, raw };
  }

  async function pipe(data, transform) {
    const stream = new Blob([data]).stream().pipeThrough(transform);
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  // Returns a body to send instead of the original, or null to send it as is.
  // Redacted JSON goes back in the same encoding: gzip stays gzip.
  async function redactPayload(body) {
    const read = await readBody(body);
    if (!read) return null;
    const text = await redactBody(read.text);
    if (text === null) return read.raw; // a used-up stream is replaced by its bytes
    if (read.gzip) return pipe(new TextEncoder().encode(text), new CompressionStream("gzip"));
    return typeof body === "string" ? text : new TextEncoder().encode(text);
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
        if (init && init.body != null) {
          const newBody = await redactPayload(init.body);
          if (newBody !== null) init = Object.assign({}, init, { body: newBody });
        } else if (isReq && input.body) {
          const newBody = await redactPayload(await input.clone().arrayBuffer());
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

  // XMLHttpRequest: send() is held back while the body is redacted, then the
  // real send() goes out with the new body. Synchronous requests can't wait,
  // so they pass through unchanged.
  const XHR = window.XMLHttpRequest && window.XMLHttpRequest.prototype;
  if (XHR) {
    const origOpen = XHR.open, origSend = XHR.send;
    const META = Symbol("promptRedaction");
    XHR.open = function (method, url, async) {
      this[META] = { method, url: String(url), async: arguments.length < 3 || async !== false };
      return origOpen.apply(this, arguments);
    };
    XHR.send = function (body) {
      const meta = this[META];
      if (!meta || !meta.async || body == null || !isTarget(meta.url, meta.method)) {
        return origSend.apply(this, arguments);
      }
      const xhr = this;
      redactPayload(body)
        .catch((err) => {
          console.warn("[AI Prompt Redaction] redaction failed, request sent unchanged:", err);
          return null;
        })
        .then((newBody) => {
          try { origSend.call(xhr, newBody === null ? body : newBody); }
          catch (_) { /* the page aborted the request while we were redacting */ }
        });
    };
  }
})();
