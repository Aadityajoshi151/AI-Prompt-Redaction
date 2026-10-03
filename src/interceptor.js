/*
 * Runs in the page's MAIN world at document_start, before claude.ai's own code,
 * so every fetch() and XMLHttpRequest goes through these wrappers. Bodies sent
 * to claude.ai's API have their user text redacted before the request leaves
 * the browser. claude.ai uses two formats, depending on the session:
 *  - JSON to /api/ (gzip-compressed for larger requests): the TEXT_KEYS fields.
 *  - Protocol Buffers to /claudeai-rpc/: every text field in the message.
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

  // Debug mode, for when claude.ai changes how it sends messages. In the
  // claude.ai console: localStorage.setItem("aprDebug", "1"), then reload.
  // Logs the structure of requests to claude.ai (key names, sizes), never content.
  const DEBUG = (() => {
    try { return window.localStorage.getItem("aprDebug") === "1"; } catch (_) { return false; }
  })();

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
  // Debug only: what was changed in a request (where, how long the text was,
  // and which kinds of placeholder went in). Never the text itself.
  const noteChange = (log, where, before, after) => {
    if (!log || before === after) return;
    const types = [...after.matchAll(/\[REDACTED_([A-Z0-9_]+?)_[0-9a-f]{6}\]/g)].map((m) => m[1]);
    log.push({ where, length: before.length, redacted: types });
  };

  async function redactBody(body, log) {
    if (typeof body !== "string" || body[0] !== "{" && body[0] !== "[") return null;
    let data;
    try { data = JSON.parse(body); } catch (_) { return null; }
    const fields = collect(data, []);
    if (!fields.length) return null;
    const texts = await redactStrings(fields.map(([obj, key]) => obj[key]));
    if (!texts) return null;
    fields.forEach(([obj, key], i) => { noteChange(log, "json key " + key, obj[key], texts[i]); obj[key] = texts[i]; });
    return JSON.stringify(data);
  }

  // Bodies arrive as text, bytes, Blobs or streams. Returns { text, bytes,
  // gzip, raw } (bytes: the body after any gzip is undone, null for text
  // bodies; raw: the original bytes, when reading used the body up), or null
  // when the body isn't something we can read (FormData, URLSearchParams).
  async function readBody(body) {
    if (typeof body === "string") return { text: body, bytes: null, gzip: false, raw: null };
    let bytes, raw = null;
    if (ArrayBuffer.isView(body)) bytes = new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    else if (Object.prototype.toString.call(body) === "[object ArrayBuffer]") bytes = new Uint8Array(body);
    else if (typeof Blob === "function" && body instanceof Blob) bytes = new Uint8Array(await body.arrayBuffer());
    else if (typeof ReadableStream === "function" && body instanceof ReadableStream) {
      bytes = raw = new Uint8Array(await new Response(body).arrayBuffer());
    } else return null;
    const gzip = bytes[0] === 0x1f && bytes[1] === 0x8b;
    if (gzip) bytes = await pipe(bytes, new DecompressionStream("gzip"));
    return { text: new TextDecoder().decode(bytes), bytes, gzip, raw };
  }

  async function pipe(data, transform) {
    const stream = new Blob([data]).stream().pipeThrough(transform);
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  // ---------- Protocol Buffers (claude.ai's /claudeai-rpc/ requests) ----------
  // The schema isn't published, so messages are read by wire format alone:
  // every length-delimited field is either a nested message, text, or bytes.

  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  // Text without control characters (tab, newline and carriage return aside).
  const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/;
  const MAX_DEPTH = 32;

  function utf8(bytes) {
    try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch (_) { return null; }
  }

  // Parses one message into fields: { field, wire, start, valueStart, end,
  // kind, children?, text? } with offsets into `bytes`. kind is "varint",
  // "fixed64", "fixed32", "message", "string" or "bytes". Null if not protobuf.
  function parseProto(bytes, depth) {
    const out = [];
    let i = 0;
    const varint = () => {
      let v = 0, shift = 0;
      for (;;) {
        if (i >= bytes.length || shift > 63) throw new Error("bad varint");
        const b = bytes[i++];
        v += (b & 0x7f) * Math.pow(2, shift);
        if (!(b & 0x80)) return v;
        shift += 7;
      }
    };
    try {
      while (i < bytes.length) {
        const start = i, tag = varint(), field = Math.floor(tag / 8), wire = tag % 8;
        if (field < 1) return null;
        const f = { field, wire, start, valueStart: i, end: 0, kind: "" };
        if (wire === 0) { varint(); f.kind = "varint"; }
        else if (wire === 1) { i += 8; f.kind = "fixed64"; }
        else if (wire === 5) { i += 4; f.kind = "fixed32"; }
        else if (wire === 2) {
          const len = varint();
          f.valueStart = i;
          i += len;
          if (i > bytes.length) return null;
          const part = bytes.subarray(f.valueStart, i);
          const text = utf8(part);
          const children = len && depth < MAX_DEPTH ? parseProto(part, depth + 1) : null;
          // Short text can parse as a message by accident ("P1" is a valid
          // varint field). So bytes that read as clean text count as a message
          // only if the parse found a length-prefixed sub-field, whose length
          // has to fit exactly: real messages have that, stray text almost never.
          const cleanText = text !== null && !CONTROL.test(text);
          const structured = children && children.some((c) => c.wire === 2);
          if (children && children.length && (!cleanText || structured)) { f.kind = "message"; f.children = children; }
          else if (text !== null) { f.kind = "string"; f.text = text; }
          else f.kind = "bytes";
        } else return null;
        if (i > bytes.length) return null;
        f.end = i;
        out.push(f);
      }
      return out;
    } catch (_) { return null; }
  }

  function encodeVarint(n) {
    const out = [];
    while (n > 127) { out.push((n % 128) | 0x80); n = Math.floor(n / 128); }
    out.push(n);
    return out;
  }

  // Rebuilds a message, re-encoding only the fields marked changed (and the
  // lengths of the messages that contain them); everything else is copied as is.
  function encodeProto(bytes, fields) {
    const parts = [];
    for (const f of fields) {
      if (!f.changed) { parts.push(bytes.subarray(f.start, f.end)); continue; }
      const value = f.kind === "message"
        ? encodeProto(bytes.subarray(f.valueStart, f.end), f.children)
        : new TextEncoder().encode(f.text);
      parts.push(new Uint8Array(encodeVarint(f.field * 8 + 2)), new Uint8Array(encodeVarint(value.length)), value);
    }
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) { out.set(p, at); at += p.length; }
    return out;
  }

  // Every text field worth scanning, with the chain of messages that hold it.
  function collectStrings(fields, parents, out) {
    for (const f of fields) {
      if (f.kind === "message") collectStrings(f.children, parents.concat(f), out);
      else if (f.kind === "string" && f.text.length >= 2 && !UUID.test(f.text)) out.push({ field: f, parents });
    }
    return out;
  }

  // Connect-RPC streaming bodies wrap the message in a 5-byte envelope:
  // 1 flag byte (bit 0 = compressed) + 4-byte big-endian length.
  async function openEnvelope(bytes) {
    if (bytes.length >= 5 && bytes[0] <= 1) {
      const len = ((bytes[1] << 24) | (bytes[2] << 16) | (bytes[3] << 8) | bytes[4]) >>> 0;
      if (len === bytes.length - 5) {
        const compressed = bytes[0] === 1;
        const message = compressed ? await pipe(bytes.subarray(5), new DecompressionStream("gzip")) : bytes.subarray(5);
        return { message, enveloped: true, compressed };
      }
    }
    return { message: bytes, enveloped: false, compressed: false };
  }

  // Returns the redacted message bytes, or null if nothing changed.
  async function redactProto(bytes, log) {
    const env = await openEnvelope(bytes);
    const fields = parseProto(env.message, 0);
    if (!fields) return null;
    const strings = collectStrings(fields, [], []);
    if (!strings.length) return null;
    const texts = await redactStrings(strings.map((s) => s.field.text));
    if (!texts) return null;
    strings.forEach((s, i) => {
      if (texts[i] === s.field.text) return;
      noteChange(log, "field " + s.parents.concat(s.field).map((f) => f.field).join("."), s.field.text, texts[i]);
      s.field.text = texts[i];
      s.field.changed = true;
      for (const p of s.parents) p.changed = true;
    });
    let message = encodeProto(env.message, fields);
    if (!env.enveloped) return message;
    if (env.compressed) message = await pipe(message, new CompressionStream("gzip"));
    const out = new Uint8Array(5 + message.length);
    out[0] = env.compressed ? 1 : 0;
    new DataView(out.buffer).setUint32(1, message.length);
    out.set(message, 5);
    return out;
  }

  // Returns a body to send instead of the original, or null to send it as is.
  // The result keeps the original encoding: gzip stays gzip.
  async function redactPayload(body, url) {
    const read = await readBody(body);
    if (!read) return null;
    const log = DEBUG ? [] : null;
    let out = await redactBody(read.text, log);
    if (out !== null) out = typeof body === "string" && !read.gzip ? out : new TextEncoder().encode(out);
    else if (read.bytes && isRpc(url)) out = await redactProto(read.bytes, log);
    if (log && log.length) console.log("[AI Prompt Redaction debug] redacted", JSON.stringify({ path: sameOriginPath(url), changes: log }));
    if (out === null) return read.raw; // a used-up stream is replaced by its bytes
    return read.gzip ? pipe(out, new CompressionStream("gzip")) : out;
  }

  // ---------- debug output ----------
  // Structure only: key names, field numbers, string lengths, file names/types/sizes.
  function shape(v) {
    if (Array.isArray(v)) return v.slice(0, 5).map(shape);
    if (v && typeof v === "object") return Object.fromEntries(Object.keys(v).map((k) => [k, shape(v[k])]));
    return typeof v === "string" ? "<string " + v.length + ">" : typeof v;
  }
  function protoShape(fields) {
    return fields.map((f) => [f.field,
      f.kind === "message" ? protoShape(f.children)
        : f.kind === "string" ? "<string " + f.text.length + ">"
        : f.kind === "bytes" ? "<bytes " + (f.end - f.valueStart) + ">" : f.kind]);
  }

  async function describeBinary(bytes) {
    const info = { size: bytes.length, firstBytes: [...bytes.subarray(0, 8)].map((b) => b.toString(16).padStart(2, "0")).join(" ") };
    try {
      const env = await openEnvelope(bytes);
      if (env.enveloped) info.envelope = env.compressed ? "compressed" : "plain";
      const fields = parseProto(env.message, 0);
      if (fields) info.protobuf = protoShape(fields);
    } catch (err) { info.error = String(err); }
    return info;
  }

  function contentType(input, init) {
    try {
      const h = init && init.headers ? new Headers(init.headers) : input && input.headers;
      return (h && h.get && h.get("content-type")) || "";
    } catch (_) { return ""; }
  }

  async function debugLog(via, method, url, body, type) {
    if (!/^(POST|PUT|PATCH)$/i.test(method || "GET")) return;
    try {
      const u = new URL(url, location.href);
      if (u.origin !== location.origin) return;
      const info = { via, method, path: u.pathname, handled: isTarget(url, method) };
      if (type) info.type = type;
      if (body == null) info.body = "none";
      else if (typeof FormData === "function" && body instanceof FormData) {
        info.body = "FormData";
        info.fields = [...body.entries()].map(([k, v]) =>
          typeof v === "string" ? [k, "<string " + v.length + ">"] : [k, "file " + v.name + " (" + v.type + ", " + v.size + " bytes)"]);
      } else if (typeof ReadableStream === "function" && body instanceof ReadableStream) info.body = "stream (not inspected)";
      else {
        const read = await readBody(body);
        info.body = read ? (read.gzip ? "gzip " : "") + (read.bytes ? "bytes" : "text") : Object.prototype.toString.call(body);
        if (read) {
          try { info.json = shape(JSON.parse(read.text)); }
          catch (_) { info.binary = await describeBinary(read.bytes || new TextEncoder().encode(read.text)); }
        }
      }
      console.log("[AI Prompt Redaction debug]", JSON.stringify(info));
    } catch (err) {
      console.log("[AI Prompt Redaction debug] could not describe request:", err);
    }
  }

  // claude.ai sends messages either as JSON to /api/ or as Protocol Buffers
  // to /claudeai-rpc/, depending on the session.
  function sameOriginPath(url) {
    try {
      const u = new URL(url, location.href);
      return u.origin === location.origin ? u.pathname : null;
    } catch (_) { return null; }
  }
  const isRpc = (url) => (sameOriginPath(url) || "").startsWith("/claudeai-rpc/");
  function isTarget(url, method) {
    if (!/^(POST|PUT|PATCH)$/i.test(method || "GET")) return false;
    const path = sameOriginPath(url);
    return path !== null && (path.startsWith("/api/") || path.startsWith("/claudeai-rpc/"));
  }

  const origFetch = window.fetch;

  async function redactingFetch(input, init) {
    try {
      const isReq = input instanceof Request;
      const url = isReq ? input.url : String(input);
      const method = (init && init.method) || (isReq ? input.method : "GET");
      if (DEBUG) {
        await debugLog("fetch", method, url, init && init.body != null ? init.body
          : isReq && input.body ? await input.clone().arrayBuffer() : null, contentType(input, init));
      }

      if (isTarget(url, method)) {
        if (init && init.body != null) {
          const newBody = await redactPayload(init.body, url);
          if (newBody !== null) init = Object.assign({}, init, { body: newBody });
        } else if (isReq && input.body) {
          const newBody = await redactPayload(await input.clone().arrayBuffer(), url);
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
      if (DEBUG && meta) debugLog("xhr", meta.method, meta.url, body);
      if (!meta || !meta.async || body == null || !isTarget(meta.url, meta.method)) {
        return origSend.apply(this, arguments);
      }
      const xhr = this;
      redactPayload(body, meta.url)
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
