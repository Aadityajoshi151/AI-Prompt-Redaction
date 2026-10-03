// Runs interceptor.js (page world) and bridge.js + detectors.js (content-script
// world) against a fake page and checks what would go over the network.
// Run with: node test/interceptor.test.js
const vm = require("vm"), fs = require("fs"), path = require("path"), assert = require("assert");
const zlib = require("zlib");

const load = (ctx, files) => {
  for (const f of files) vm.runInContext(fs.readFileSync(path.join(__dirname, "..", f), "utf8"), ctx);
};

// A fake page: fetch records what would be sent; postMessage is delivered
// asynchronously to every listener, like window.postMessage in a browser.
// Both worlds share it here, as they share window.postMessage in a real tab.
function makePage(settings) {
  const sent = [], toasts = [], listeners = [], xhrSent = [];
  // Stand-in for the browser's XMLHttpRequest: records what send() receives.
  class FakeXHR {
    open(method, url) { this.url = url; }
    send(body) { xhrSent.push(body); }
  }
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
    Symbol, Blob, Response, ReadableStream, TextEncoder, TextDecoder, CompressionStream, DecompressionStream,
    Uint8Array, DataView, Error,
    XMLHttpRequest: FakeXHR,
    // Content-script side: extension storage and the on-page indicator.
    chrome: { storage: {
      sync: { get: async (d) => ({ ...d, ...settings }) },
      local: { get: async () => ({}), set: async () => {} },
      onChanged: { addListener() {} } } },
    PromptRedactionUI: { setSettings() {}, onOutgoing() {}, onRedacted: (findings, matches) => toasts.push({ findings, matches }) },
  };
  win.window = win; win.globalThis = win;
  const ctx = vm.createContext(win);
  self = vm.runInContext("window", ctx);
  return { win, sent, toasts, xhrSent, ctx };
}

// Waits for a condition instead of a fixed delay, so slow CI machines don't fail.
const until = async (cond, ms = 5000) => {
  for (const end = Date.now() + ms; !cond() && Date.now() < end;) await new Promise((r) => setTimeout(r, 5));
};

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

  // ---------- gzip, binary and stream bodies (claude.ai gzips larger requests) ----------
  const withFile = (extra) => JSON.stringify({ prompt: "see file",
    attachments: [{ file_name: "notes.txt", extracted_content: "contact jane@acme.com" + (extra || "") }] });
  const gz = (text) => new Uint8Array(zlib.gzipSync(text));
  const attachmentOf = (buf) => JSON.parse(zlib.gunzipSync(Buffer.from(buf)).toString()).attachments[0].extracted_content;
  sent.length = 0; toasts.length = 0;

  await post(win, url, gz(withFile()));
  assert.strictEqual(attachmentOf(sent[0]), "contact [REDACTED_EMAIL_2]", "gzip bytes: attachment redacted, still gzip");
  await post(win, url, new Blob([gz(withFile(" again"))]));
  assert.strictEqual(attachmentOf(sent[1]), "contact [REDACTED_EMAIL_2] again", "gzip Blob");
  await post(win, url, new TextEncoder().encode(withFile()));
  assert.match(new TextDecoder().decode(sent[2]), /contact \[REDACTED_EMAIL_2\]/, "plain bytes");
  await win.fetch(url, { method: "POST", body: new Blob([gz(withFile())]).stream(), duplex: "half" });
  assert.strictEqual(attachmentOf(sent[3]), "contact [REDACTED_EMAIL_2]", "gzip stream");
  const clean = gz('{"prompt":"nothing to hide"}');
  await post(win, url, clean);
  assert.strictEqual(sent[4], clean, "unchanged bodies are sent as the same object");
  assert.strictEqual(toasts.length, 4, "a toast for each redacted request");

  // ---------- XMLHttpRequest ----------
  const xhr = (method, u, body, async) => { const x = new win.XMLHttpRequest(); x.open(method, u, async); x.send(body); };
  xhr("POST", url, gz(withFile()));
  assert.strictEqual(page.xhrSent.length, 0, "send waits for redaction");
  await until(() => page.xhrSent.length > 0);
  await new Promise((r) => setTimeout(r, 20)); // room for a wrong second send to show up
  assert.strictEqual(page.xhrSent.length, 1, "then goes out once");
  assert.strictEqual(attachmentOf(page.xhrSent[0]), "contact [REDACTED_EMAIL_2]", "gzip XHR body");
  xhr("GET", url, '{"prompt":"a@b.com"}');
  xhr("POST", "https://elsewhere.com/api/x", '{"prompt":"a@b.com"}');
  xhr("POST", url, '{"prompt":"a@b.com"}', false);
  assert.deepStrictEqual(page.xhrSent.slice(1), Array(3).fill('{"prompt":"a@b.com"}'),
    "GET, other origins and synchronous XHRs pass through unchanged");

  // ---------- Protocol Buffers over /claudeai-rpc/ (claude.ai's newer transport) ----------
  // Minimal encoder/decoder, independent of the one in interceptor.js.
  const vint = (n) => { const o = []; while (n > 127) { o.push((n & 127) | 128); n = Math.floor(n / 128); } o.push(n); return Buffer.from(o); };
  const str = (field, v) => { const b = Buffer.isBuffer(v) ? v : Buffer.from(v); return Buffer.concat([vint(field * 8 + 2), vint(b.length), b]); };
  const num = (field, n) => Buffer.concat([vint(field * 8), vint(n)]);
  const f32 = (field) => Buffer.concat([vint(field * 8 + 5), Buffer.from([1, 2, 3, 4])]);
  const msg = (...parts) => Buffer.concat(parts);
  // Decodes one level: { fieldNumber: [values...] }, length-delimited values as Buffers.
  const dec = (buf) => {
    const out = {}; let i = 0;
    const rv = () => { let v = 0, sh = 0, b; do { b = buf[i++]; v += (b & 127) * 2 ** sh; sh += 7; } while (b & 128); return v; };
    while (i < buf.length) {
      const tag = rv(), field = Math.floor(tag / 8), wire = tag % 8;
      let v;
      if (wire === 0) v = rv();
      else if (wire === 5) { v = buf.subarray(i, i + 4); i += 4; }
      else { const len = rv(); v = buf.subarray(i, i + len); i += len; }
      (out[field] = out[field] || []).push(v);
    }
    assert.strictEqual(i, buf.length, "decodes to exactly the end");
    return out;
  };
  const rpc = "/claudeai-rpc/anthropic.bard.api.v1alpha.ConversationService/PerformAction";
  const ID1 = "66c882d2-8745-4b1f-bfed-6ae4bbd3f9b3", ID2 = "550e8400-e29b-41d4-a716-446655440000";
  const blob = Buffer.from(Array.from({ length: 32 }, (_, k) => 200 + (k % 50))); // not valid UTF-8
  const header = str(1, msg(str(1, msg(str(1, "claude-sonnet-4-5-xyz"), num(2, 1))), str(2, ID1), num(3, 1),
    str(7, msg(num(1, 1), num(2, 0), num(10, 1))), str(14, f32(12)), str(15, blob)));
  const action = (text, attachment) => new Uint8Array(msg(header, str(2, msg(str(1, ID1), str(2, ID2), str(3, text),
    str(12, "Asia/Calcutta"), str(13, f32(12)), ...(attachment ? [str(15, msg(num(2, 1), str(3, "txt"), str(4, attachment)))] : []), num(18, 1)))));
  const sendRpc = async (body, u) => { sent.length = 0; await post(win, u || rpc, body); return sent[0]; };
  const text = (b) => Buffer.from(b).toString();

  let out = dec(Buffer.from(await sendRpc(action("please mail me at a@b.com about it"))));
  let m = dec(out[2][0]);
  assert.strictEqual(text(m[3][0]), "please mail me at [REDACTED_EMAIL_1] about it", "protobuf: message text redacted");
  assert.deepStrictEqual([text(m[1][0]), text(m[2][0]), text(m[12][0]), m[18][0]], [ID1, ID2, "Asia/Calcutta", 1], "ids and other fields untouched");
  assert.ok(Buffer.from(out[1][0]).equals(header.subarray(2)), "unrelated message copied byte for byte");

  const fileText = "notes\n".repeat(40) + "contact jane@acme.com or account number: 9876543210\n" + "more\n".repeat(40);
  out = dec(Buffer.from(await sendRpc(action("see the attached file", fileText))));
  m = dec(out[2][0]);
  const file = dec(m[15][0]);
  assert.strictEqual(text(m[3][0]), "see the attached file");
  assert.strictEqual(text(file[4][0]), fileText.replace("jane@acme.com", "[REDACTED_EMAIL_2]").replace("9876543210", "[REDACTED_BANK_ACCOUNT_1]"),
    "protobuf: attachment text redacted, lengths re-encoded");
  assert.strictEqual(text(file[3][0]), "txt");

  const untouched = action("nothing to hide here");
  assert.strictEqual(await sendRpc(untouched), untouched, "protobuf: unchanged bodies are sent as the same object");

  // Nested messages made only of printable bytes (field 4, lengths over 31)
  // read as text; they must still be handled as messages, or their lengths break.
  const wrapped = new Uint8Array(msg(str(2, msg(str(4, msg(str(1, "this block of text mentions a@b.com somewhere inside")))))));
  out = dec(dec(dec(Buffer.from(await sendRpc(wrapped)))[2][0])[4][0]);
  assert.strictEqual(text(out[1][0]), "this block of text mentions [REDACTED_EMAIL_1] somewhere inside", "protobuf: string wrapper message");

  // Connect streaming envelope: flag byte + 4-byte length, plain and gzip.
  const envelope = (flag, payload) => { const b = Buffer.alloc(5 + payload.length); b[0] = flag; b.writeUInt32BE(payload.length, 1); payload.copy(b, 5); return new Uint8Array(b); };
  const inner = Buffer.from(action("streamed a@b.com"));
  let env = Buffer.from(await sendRpc(envelope(0, inner)));
  assert.strictEqual(env.readUInt32BE(1), env.length - 5, "envelope length updated");
  assert.strictEqual(text(dec(dec(env.subarray(5))[2][0])[3][0]), "streamed [REDACTED_EMAIL_1]", "protobuf in a plain envelope");
  env = Buffer.from(await sendRpc(envelope(1, zlib.gzipSync(inner))));
  assert.strictEqual(env[0], 1, "compressed envelope stays compressed");
  assert.strictEqual(text(dec(dec(zlib.gunzipSync(env.subarray(5)))[2][0])[3][0]), "streamed [REDACTED_EMAIL_1]", "protobuf in a gzip envelope");

  // Short text that happens to parse as a message ("P1" = field 10, varint 49) stays text.
  out = dec(Buffer.from(await sendRpc(new Uint8Array(msg(str(3, "P1"), str(4, "mail a@b.com"))))));
  assert.deepStrictEqual([text(out[3][0]), text(out[4][0])], ["P1", "mail [REDACTED_EMAIL_1]"], "protobuf: text that looks like a message");

  const onApi = action("mail a@b.com");
  assert.strictEqual(await sendRpc(onApi, url), onApi, "binary bodies outside /claudeai-rpc/ are left alone");

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
