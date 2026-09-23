// Runs indicator.js + bridge.js in jsdom with small stand-ins for what jsdom
// lacks (Highlight API, innerText, layout). Needs: npm install
// Run with: node test/indicator.test.js
const { JSDOM } = require("jsdom");
const fs = require("fs"), path = require("path"), assert = require("assert");

const dom = new JSDOM(`<!doctype html><html><body>
  <div id="chat"><div><p>my email is jane@acme.com, server 10.0.0.7</p></div></div>
  <fieldset><div id="box" contenteditable="true"><p></p></div></fieldset>
</body></html>`, { runScripts: "outside-only", url: "https://claude.ai/chat/1", pretendToBeVisual: true });
const w = dom.window;

const regs = {};
w.Highlight = class { constructor() { this.s = new Set(); } add(r) { this.s.add(r); } clear() { this.s.clear(); } get size() { return this.s.size; } };
w.CSS = { highlights: { set: (k, v) => (regs[k] = v) } };
Object.defineProperty(w.HTMLElement.prototype, "innerText", { get() { return this.textContent; } });
w.Range.prototype.getClientRects = () => [];
w.Range.prototype.toString = function () { return this.startContainer.data.slice(this.startOffset, this.endOffset); };

const store = { sync: {}, local: {} };
w.chrome = { storage: {
  sync: { get: async (d) => ({ ...d, ...store.sync }), set: async (o) => Object.assign(store.sync, o) },
  local: { get: async () => store.local, set: async (o) => Object.assign(store.local, o) },
  onChanged: { addListener() {} } } };

for (const f of ["src/detectors.js", "src/indicator.js", "src/bridge.js"]) {
  w.eval(fs.readFileSync(path.join(__dirname, "..", f), "utf8"));
}
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const marked = (name) => [...regs[name].s].map(String).sort();
// jsdom leaves event.source null on postMessage; real browsers set it.
const post = (data) => w.dispatchEvent(new w.MessageEvent("message", { data, source: w, origin: "https://claude.ai" }));

(async () => {
  await wait(50);
  const box = w.document.getElementById("box");
  box.firstChild.textContent = "deploy with AKIAIOSFODNN7EXAMPLE to db.prod.internal";
  box.dispatchEvent(new w.Event("input", { bubbles: true }));
  await wait(200);
  const pill = w.document.querySelector(".apr-pill");
  assert.ok(pill, "label shown while typing");
  assert.match(pill.textContent, /2 items will be redacted/);
  assert.strictEqual(pill.parentNode, w.document.documentElement, "UI mounted outside <body>");
  assert.deepStrictEqual(marked("apr-pending"), ["AKIAIOSFODNN7EXAMPLE", "db.prod.internal"]);

  post({ tag: "__prompt_redaction__", type: "redacted", findings: { EMAIL: 1, IPV4: 1 },
    matches: [{ id: "EMAIL", value: "jane@acme.com", placeholder: "[REDACTED_EMAIL_1]" },
              { id: "IPV4", value: "10.0.0.7", placeholder: "[REDACTED_IPV4_1]" }] });
  await wait(600);
  assert.match(w.document.querySelector(".apr-toast").textContent, /Redacted 2 items before sending/);
  assert.deepStrictEqual(marked("apr-sent"), ["10.0.0.7", "jane@acme.com"]);
  assert.strictEqual(store.local.stats.total, 2);

  const reply = w.document.createElement("p");
  reply.textContent = "I'll email [REDACTED_EMAIL_1] once [REDACTED_IPV4_1] is up.";
  w.document.getElementById("chat").appendChild(reply);
  await wait(600);
  assert.deepStrictEqual(marked("apr-placeholder"), ["[REDACTED_EMAIL_1]", "[REDACTED_IPV4_1]"]);

  box.firstChild.textContent = "";
  await wait(700);
  assert.ok(!w.document.querySelector(".apr-pill"), "label hidden after box clears");
  assert.strictEqual(regs["apr-pending"].size, 0);
  console.log("indicator: all checks passed");
  process.exit(0);
})().catch((e) => { console.error("indicator: FAIL\n", e.message); process.exit(1); });
