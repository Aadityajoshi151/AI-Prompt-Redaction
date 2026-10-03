// Runs interceptor.js (page world) and bridge.js + detectors.js (content-script
// world) against a fake page and checks what would go over the network.
// Run with: node test/interceptor.test.js
const vm = require("vm"), fs = require("fs"), path = require("path"), assert = require("assert");

const load = (ctx, files) => {
  for (const f of files) vm.runInContext(fs.readFileSync(path.join(__dirname, "..", f), "utf8"), ctx);
};

// A fake page: fetch records what would be sent; postMessage is delivered
// asynchronously to every listener, like window.postMessage in a browser.
// Both worlds share it here, as they share window.postMessage in a real tab.
function makePage(settings) {
  const sent = [], toasts = [], listeners = [];
  let self; // the sandbox's global as scripts see it (vm wraps win), used as event.source
  const win = {
    location: { origin: "https://claude.ai", href: "https://claude.ai/chat/x" },
    addEventListener: (type, fn) => { if (type === "message") listeners.push(fn); },
    postMessage: (data) => setTimeout(() => {
      for (const fn of listeners) fn({ source: self, data: JSON.parse(JSON.stringify(data)) });
    }, 0),
    fetch: async (input, init) => {
      sent.push(init && init.body !== undefined ? init.body : typeof input === "string" ? null : await input.text());
      return { ok: true };
    },
    Request, URL, JSON, console, Object, Array, Set, Map, Math, Promise, String, Date, setTimeout, clearTimeout,
    // Content-script side: extension storage and the on-page indicator.
    chrome: { storage: {
      sync: { get: async (d) => ({ ...d, ...settings }) },
      local: { get: async () => ({}), set: async () => {} },
      onChanged: { addListener() {} } } },
    PromptRedactionUI: { setSettings() {}, onRedacted: (findings, matches) => toasts.push({ findings, matches }) },
  };
  win.window = win; win.globalThis = win;
  const ctx = vm.createContext(win);
  self = vm.runInContext("window", ctx);
  return { win, sent, toasts, ctx };
}

const url = "/api/organizations/o/chat_conversations/c/completion";
const post = (win, u, body) => win.fetch(u, { method: "POST", body });

(async () => {
  // ---------- normal case ----------
  const page = makePage({});
  load(page.ctx, ["src/interceptor.js", "src/detectors.js", "src/bridge.js"]);
  const { win, sent, toasts } = page;

  await post(win, url, JSON.stringify({
    prompt: "my key is sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123, mail me at a@b.com",
    attachments: [{ file_name: "env.txt", extracted_content: "DB_PASSWORD=hunter2hunter2" }],
    parent_message_uuid: "550e8400-e29b-41d4-a716-446655440000" }));
  await win.fetch(new Request("https://claude.ai" + url, { method: "POST", body: '{"prompt":"again a@b.com"}' }));
  await win.fetch("/api/other", { method: "GET" });
  await post(win, "https://elsewhere.com/api/x", '{"prompt":"a@b.com"}');
  await post(win, url, '{"prompt":"nothing to hide"}');

  const first = JSON.parse(sent[0]);
  assert.strictEqual(first.prompt, "my key is [REDACTED_ANTHROPIC_KEY_1], mail me at [REDACTED_EMAIL_1]");
  assert.strictEqual(first.attachments[0].extracted_content, "DB_PASSWORD=[REDACTED_SECRET_ASSIGNMENT_1]");
  assert.strictEqual(first.parent_message_uuid, "550e8400-e29b-41d4-a716-446655440000", "ids untouched");
  assert.strictEqual(JSON.parse(sent[1]).prompt, "again [REDACTED_EMAIL_1]", "Request objects + stable placeholders");
  assert.strictEqual(sent[2], null, "GET passes through");
  assert.strictEqual(sent[3], '{"prompt":"a@b.com"}', "other origins untouched");
  assert.strictEqual(sent[4], '{"prompt":"nothing to hide"}', "nothing found: body unchanged");

  assert.strictEqual(toasts.length, 2, "the content script shows a toast per redacted request");
  // JSON round-trip: objects from the vm sandbox have a different Object.prototype
  assert.deepStrictEqual(JSON.parse(JSON.stringify(toasts[0].findings)), { ANTHROPIC_KEY: 1, EMAIL: 1, SECRET_ASSIGNMENT: 1 });
  assert.ok(toasts[0].matches.some((m) => m.value === "a@b.com" && m.placeholder === "[REDACTED_EMAIL_1]"));

  // ---------- settings come from the content script ----------
  const custom = makePage({ customTerms: ["Project Falcon"], overrides: { EMAIL: false } });
  load(custom.ctx, ["src/interceptor.js", "src/detectors.js", "src/bridge.js"]);
  await post(custom.win, url, '{"prompt":"project falcon update for a@b.com"}');
  assert.strictEqual(JSON.parse(custom.sent[0]).prompt, "[REDACTED_CUSTOM_1] update for a@b.com", "custom terms and switches apply");

  const off = makePage({ enabled: false });
  load(off.ctx, ["src/interceptor.js", "src/detectors.js", "src/bridge.js"]);
  await post(off.win, url, '{"prompt":"a@b.com"}');
  assert.strictEqual(off.sent[0], '{"prompt":"a@b.com"}', "redaction switched off");
  assert.strictEqual(off.toasts.length, 0);

  // ---------- the page script loads before the content script ----------
  const late = makePage({});
  load(late.ctx, ["src/interceptor.js"]);
  const pendingSend = post(late.win, url, '{"prompt":"a@b.com"}');
  await new Promise((r) => setTimeout(r, 20));
  load(late.ctx, ["src/detectors.js", "src/bridge.js"]);
  await pendingSend;
  assert.strictEqual(JSON.parse(late.sent[0]).prompt, "[REDACTED_EMAIL_1]", "waits for the content script to start");

  // ---------- no content script at all: fail open after the timeout ----------
  const alone = makePage({});
  load(alone.ctx, ["src/interceptor.js"]);
  const warn = console.warn; console.warn = () => {};
  await post(alone.win, url, '{"prompt":"a@b.com"}');
  console.warn = warn;
  assert.strictEqual(alone.sent[0], '{"prompt":"a@b.com"}', "sent unchanged when nobody answers");

  console.log("interceptor: all checks passed");
})().catch((e) => { console.error("interceptor: FAIL\n", e.message); process.exit(1); });
