/*
 * On-page indicators (content-script world). Styles live in indicator.css,
 * injected by the manifest so claude.ai's CSP can't block them.
 *
 * 1. While typing: text that will be redacted is highlighted in the message
 *    box, and a label above it says how many items will be redacted.
 * 2. After sending: a toast confirms what was redacted, and the original
 *    values stay marked in the chat, with a tooltip saying what the AI got.
 * 3. After a reload the chat contains [REDACTED_…] placeholders; those are
 *    styled as redaction bars.
 *
 * Highlights use the CSS Custom Highlight API, which colors text ranges
 * without modifying claude.ai's DOM (editing React-managed nodes can break
 * the app). Without that API, the label, toast and tooltips still work.
 */
(function () {
  "use strict";
  const R = globalThis.PromptRedaction;
  const EDITABLE = '[contenteditable="true"], textarea';
  const PH_RE = /\[REDACTED_([A-Z0-9_]+?)_\d+\]/g;

  let settings = { enabled: true, overrides: {}, customTerms: [] };
  const sent = new Map();      // original value -> placeholder the AI received
  let pageTips = [];           // [{range, text}] for marks in the chat
  let pendingTips = [];        // [{range, text}] for marks in the message box

  // ---------- highlight registry (degrades to no-op) ----------
  let HL = null;
  try {
    if (globalThis.CSS && CSS.highlights && typeof Highlight === "function") {
      HL = { pending: new Highlight(), sent: new Highlight(), placeholder: new Highlight() };
      CSS.highlights.set("apr-pending", HL.pending);
      CSS.highlights.set("apr-sent", HL.sent);
      CSS.highlights.set("apr-placeholder", HL.placeholder);
    }
  } catch (_) { HL = null; }

  function hl(name, op, range) {
    if (!HL) return;
    try { op === "clear" ? HL[name].clear() : HL[name].add(range); }
    catch (_) { HL = null; } // e.g. unsupported through Firefox's content-script wrappers
  }

  // ---------- small DOM helpers ----------
  function make(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text) n.textContent = text;
    return n;
  }
  // Our UI lives under <html>, outside <body>, so it never touches React's tree
  // and never triggers our own MutationObserver.
  function mount(n) { if (!n.isConnected) document.documentElement.appendChild(n); }

  function summarize(findings) {
    return Object.entries(findings)
      .map(([id, n]) => R.shortName(id) + (n > 1 ? " \u00d7" + n : ""))
      .join(", ");
  }
  const plural = (n, word) => n + " " + word + (n === 1 ? "" : "s");

  function rangeOf(node, start, end) {
    const r = document.createRange();
    r.setStart(node, start);
    r.setEnd(node, end);
    return r;
  }

  function eachOccurrence(text, value, fn) {
    if (!value) return;
    let i = text.indexOf(value);
    while (i !== -1) { fn(i, i + value.length); i = text.indexOf(value, i + value.length); }
  }

  // ---------- 1. label + highlights while typing ----------
  const pill = make("div", "apr-ui apr-pill");
  pill.setAttribute("role", "status");
  pill.setAttribute("aria-live", "polite");
  const pillBar = make("span", "apr-bar");
  const pillText = make("span", "apr-pill-text");
  const pillTitle = make("span", "apr-pill-title");
  const pillDetail = make("span", "apr-pill-detail");
  pillText.append(pillTitle, pillDetail);
  pill.append(pillBar, pillText);

  let composer = null;
  let pillOn = false;
  let editTimer = 0;

  function clearPending() {
    hl("pending", "clear");
    pendingTips = [];
    if (pillOn) { pill.remove(); pillOn = false; }
  }

  function scanComposer() {
    if (!composer || !composer.isConnected || !settings.enabled) return clearPending();
    const text = composer.tagName === "TEXTAREA" ? composer.value : composer.innerText;
    const res = R.redact(text, { overrides: settings.overrides, customTerms: settings.customTerms });
    if (!res.matches.length) return clearPending();

    pillTitle.textContent = plural(res.matches.length, "item") + " will be redacted before sending";
    pillDetail.textContent = summarize(res.findings);
    mount(pill);
    pillOn = true;
    place();

    hl("pending", "clear");
    pendingTips = [];
    if (composer.tagName === "TEXTAREA") return; // no text ranges inside a textarea
    const byValue = new Map(res.matches.map((m) => [m.value, m.id]));
    const walker = document.createTreeWalker(composer, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      for (const [value, id] of byValue) {
        eachOccurrence(n.data, value, (s, e) => {
          const r = rangeOf(n, s, e);
          hl("pending", "add", r);
          pendingTips.push({ range: r, text: "Will be redacted (" + R.shortName(id) + ")" });
        });
      }
    }
  }

  function place() {
    if (!pillOn || !composer) return;
    const box = (composer.closest("fieldset") || composer).getBoundingClientRect();
    const h = pill.offsetHeight;
    let top = box.top - h - 8;
    if (top < 8) top = box.bottom + 8;
    pill.style.top = top + "px";
    pill.style.left = Math.max(8, box.left) + "px";
  }

  function onEdit(e) {
    const target = e.target && e.target.closest ? e.target.closest(EDITABLE) : null;
    if (!target) return;
    composer = target;
    clearTimeout(editTimer);
    editTimer = setTimeout(scanComposer, 120);
  }
  document.addEventListener("input", onEdit, true);
  document.addEventListener("paste", onEdit, true);
  document.addEventListener("focusin", onEdit, true);
  window.addEventListener("scroll", place, true);
  window.addEventListener("resize", place);
  // The box is cleared programmatically after sending, without an input event.
  setInterval(() => { if (pillOn) scanComposer(); }, 600);

  // ---------- 2 & 3. marks in the conversation ----------
  let pageTimer = 0;
  function schedulePageScan() {
    if (pageTimer) return; // throttle, so streaming replies can't starve it
    pageTimer = setTimeout(() => { pageTimer = 0; scanPage(); }, 400);
  }

  function scanPage() {
    if (!document.body) return;
    hl("sent", "clear");
    hl("placeholder", "clear");
    pageTips = [];
    const values = [...sent.keys()];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const t = n.data;
      const hasPh = t.indexOf("[REDACTED_") !== -1;
      const vals = values.filter((v) => t.indexOf(v) !== -1);
      if (!hasPh && !vals.length) continue;
      const parent = n.parentElement;
      if (!parent || parent.closest(EDITABLE + ", script, style, noscript")) continue;

      if (hasPh) {
        PH_RE.lastIndex = 0;
        for (let m = PH_RE.exec(t); m; m = PH_RE.exec(t)) {
          const r = rangeOf(n, m.index, m.index + m[0].length);
          hl("placeholder", "add", r);
          pageTips.push({ range: r, text: "Redacted " + R.shortName(m[1]) + " by AI Prompt Redaction. The AI never saw the original." });
        }
      }
      for (const v of vals) {
        eachOccurrence(t, v, (s, e) => {
          const r = rangeOf(n, s, e);
          hl("sent", "add", r);
          pageTips.push({ range: r, text: "Not sent. The AI received " + sent.get(v) + " instead." });
        });
      }
    }
  }

  function observe() {
    new MutationObserver(schedulePageScan)
      .observe(document.body, { subtree: true, childList: true, characterData: true });
    schedulePageScan();
  }
  if (document.body) observe();
  else document.addEventListener("DOMContentLoaded", observe, { once: true });

  // ---------- tooltips ----------
  const tip = make("div", "apr-ui apr-tip");
  let raf = 0, lastX = 0, lastY = 0;

  function hover() {
    raf = 0;
    for (const t of pendingTips.concat(pageTips)) {
      for (const rc of t.range.getClientRects()) {
        if (lastX >= rc.left - 2 && lastX <= rc.right + 2 && lastY >= rc.top - 2 && lastY <= rc.bottom + 2) {
          tip.textContent = t.text;
          mount(tip);
          const top = rc.top - tip.offsetHeight - 6;
          tip.style.top = (top < 4 ? rc.bottom + 6 : top) + "px";
          tip.style.left = Math.min(Math.max(4, rc.left), window.innerWidth - tip.offsetWidth - 4) + "px";
          return;
        }
      }
    }
    tip.remove();
  }
  document.addEventListener("mousemove", (e) => {
    if (!pendingTips.length && !pageTips.length) return;
    lastX = e.clientX; lastY = e.clientY;
    if (!raf) raf = requestAnimationFrame(hover);
  }, { passive: true });

  // ---------- toast after sending ----------
  const toast = make("div", "apr-ui apr-toast");
  toast.setAttribute("role", "status");
  toast.setAttribute("aria-live", "polite");
  const toastBar = make("span", "apr-bar");
  const toastText = make("span", "apr-pill-text");
  const toastTitle = make("span", "apr-pill-title");
  const toastDetail = make("span", "apr-pill-detail");
  toastText.append(toastTitle, toastDetail);
  toast.append(toastBar, toastText);
  let toastTimer = 0;

  function showToast(findings, count) {
    toastTitle.textContent = "Redacted " + plural(count, "item") + " before sending";
    toastDetail.textContent = summarize(findings) + ". Marked text in your message was not sent to the AI.";
    mount(toast);
    requestAnimationFrame(() => toast.classList.add("apr-on"));
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove("apr-on"), 7000);
  }

  // ---------- API used by bridge.js ----------
  globalThis.PromptRedactionUI = {
    setSettings(s) {
      settings = s;
      if (composer) scanComposer();
    },
    onRedacted(findings, matches) {
      for (const m of matches) sent.set(m.value, m.placeholder);
      clearPending();
      showToast(findings, matches.length);
      schedulePageScan();
    },
  };
})();
