// Runs interceptor.js against a fake page and checks what would go over the network.
// Run with: node test/interceptor.test.js
const vm = require("vm"), fs = require("fs"), path = require("path"), assert = require("assert");

const sent = [], posted = [];
const win = {
  location: { origin: "https://claude.ai", href: "https://claude.ai/chat/x" },
  addEventListener() {}, postMessage: (m) => posted.push(m),
  fetch: async (input, init) => {
    sent.push(init && init.body !== undefined ? init.body : typeof input === "string" ? null : await input.text());
    return { ok: true };
  },
  Request, URL, JSON, console, Object, Array, Set, Map, Math,
};
win.window = win; win.globalThis = win;
const ctx = vm.createContext(win);
for (const f of ["src/detectors.js", "src/interceptor.js"]) {
  vm.runInContext(fs.readFileSync(path.join(__dirname, "..", f), "utf8"), ctx);
}

(async () => {
  const url = "/api/organizations/o/chat_conversations/c/completion";
  await win.fetch(url, { method: "POST", body: JSON.stringify({
    prompt: "my key is sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123, mail me at a@b.com",
    attachments: [{ file_name: "env.txt", extracted_content: "DB_PASSWORD=hunter2hunter2" }],
    parent_message_uuid: "550e8400-e29b-41d4-a716-446655440000" }) });
  await win.fetch(new Request("https://claude.ai" + url, { method: "POST", body: '{"prompt":"again a@b.com"}' }));
  await win.fetch("/api/other", { method: "GET" });
  await win.fetch("https://elsewhere.com/api/x", { method: "POST", body: '{"prompt":"a@b.com"}' });

  const first = JSON.parse(sent[0]);
  assert.strictEqual(first.prompt, "my key is [REDACTED_ANTHROPIC_KEY_1], mail me at [REDACTED_EMAIL_1]");
  assert.strictEqual(first.attachments[0].extracted_content, "DB_PASSWORD=[REDACTED_SECRET_ASSIGNMENT_1]");
  assert.strictEqual(first.parent_message_uuid, "550e8400-e29b-41d4-a716-446655440000", "ids untouched");
  assert.strictEqual(JSON.parse(sent[1]).prompt, "again [REDACTED_EMAIL_1]", "Request objects + stable placeholders");
  assert.strictEqual(sent[2], null, "GET passes through");
  assert.strictEqual(sent[3], '{"prompt":"a@b.com"}', "other origins untouched");

  const events = posted.filter((p) => p.type === "redacted");
  assert.strictEqual(events.length, 2);
  // JSON round-trip: objects from the vm sandbox have a different Object.prototype
  assert.deepStrictEqual(JSON.parse(JSON.stringify(events[0].findings)), { ANTHROPIC_KEY: 1, EMAIL: 1, SECRET_ASSIGNMENT: 1 });
  assert.ok(events[0].matches.some((m) => m.value === "a@b.com" && m.placeholder === "[REDACTED_EMAIL_1]"));
  console.log("interceptor: all checks passed");
})().catch((e) => { console.error("interceptor: FAIL\n", e.message); process.exit(1); });
