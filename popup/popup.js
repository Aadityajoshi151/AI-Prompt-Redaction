(async function () {
  "use strict";
  const R = window.PromptRedaction;
  const DEFAULTS = { enabled: true, overrides: {}, customTerms: [] };
  const api = globalThis.browser ?? globalThis.chrome;
  const HOST = { origins: ["https://claude.ai/*"] };
  let settings = await api.storage.sync.get(DEFAULTS);

  const $ = (id) => document.getElementById(id);
  const save = () => api.storage.sync.set(settings);
  const isOn = (det) => settings.overrides[det.id] ?? det.defaultOn;

  // Firefox lets users withhold or revoke site access, in which case the
  // content scripts never run. Detect that and offer to grant it.
  if (!(await api.permissions.contains(HOST))) {
    $("access").hidden = false;
    $("grant").addEventListener("click", async () => {
      // Must be the first call in the click handler (user gesture).
      if (await api.permissions.request(HOST)) {
        $("access").hidden = true;
        $("access-done").hidden = false;
      }
    });
  }

  // Master switch
  $("enabled").checked = settings.enabled;
  document.body.classList.toggle("off", !settings.enabled);
  $("enabled").addEventListener("change", (e) => {
    settings.enabled = e.target.checked;
    document.body.classList.toggle("off", !settings.enabled);
    save();
  });

  // Stats
  const { stats = { total: 0 } } = await api.storage.local.get("stats");
  if (stats.total) $("stats").textContent = `${stats.total} item${stats.total === 1 ? "" : "s"} redacted so far`;

  // ---------- the two sections ----------
  for (const sec of R.SECTIONS) {
    const dets = R.DETECTORS.filter((d) => d.section === sec.id);
    const box = document.createElement("section");
    box.className = "sec";

    const head = document.createElement("div");
    head.className = "sec-head";
    const titles = document.createElement("div");
    const h2 = document.createElement("h2");
    h2.textContent = sec.title;
    const desc = document.createElement("p");
    desc.className = "muted";
    desc.textContent = sec.description;
    titles.append(h2, desc);
    const all = document.createElement("button");
    all.type = "button";
    all.className = "link";
    head.append(titles, all);
    box.appendChild(head);

    const boxes = [];
    for (const sub of sec.subsections) {
      const group = document.createElement("div");
      group.className = "group";
      const h3 = document.createElement("h3");
      h3.textContent = sub.title;
      group.appendChild(h3);
      for (const det of dets.filter((d) => d.sub === sub.id)) {
        const row = document.createElement("label");
        row.className = "row";
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.checked = isOn(det);
        cb.addEventListener("change", () => {
          settings.overrides[det.id] = cb.checked;
          save(); refresh(); renderPreview();
        });
        const text = document.createElement("span");
        const name = document.createElement("span");
        name.className = "name";
        name.textContent = det.label;
        text.appendChild(name);
        if (det.hint) {
          const hint = document.createElement("span");
          hint.className = "hint";
          hint.textContent = det.hint;
          text.appendChild(hint);
        }
        row.append(cb, text);
        group.appendChild(row);
        boxes.push([det, cb]);
      }
      box.appendChild(group);
    }

    function refresh() {
      const on = boxes.filter(([, cb]) => cb.checked).length;
      all.textContent = on > 0 ? "Turn all off" : "Turn all on";
      all.setAttribute("aria-label", `${all.textContent} in ${sec.title} (${on} of ${boxes.length} on)`);
    }
    all.addEventListener("click", () => {
      const target = !boxes.some(([, cb]) => cb.checked);
      for (const [det, cb] of boxes) { cb.checked = target; settings.overrides[det.id] = target; }
      save(); refresh(); renderPreview();
    });
    refresh();
    $("sections").appendChild(box);
  }

  // Custom terms
  $("terms").value = settings.customTerms.join("\n");
  let termTimer;
  $("terms").addEventListener("input", (e) => {
    clearTimeout(termTimer);
    termTimer = setTimeout(() => {
      settings.customTerms = e.target.value.split("\n").map((s) => s.trim()).filter(Boolean);
      save(); renderPreview();
    }, 300);
  });

  // Live test preview
  function renderPreview() {
    const out = $("preview");
    out.textContent = "";
    const src = $("test").value;
    if (!src) return;
    const { text } = R.redact(src, { overrides: settings.overrides, customTerms: settings.customTerms });
    for (const part of text.split(/(\[REDACTED_[A-Z0-9_]+?_\d+\])/)) {
      if (!part) continue;
      const m = part.match(/^\[REDACTED_([A-Z0-9_]+?)_\d+\]$/);
      if (m) {
        const s = document.createElement("span");
        s.className = "bar";
        s.textContent = R.shortName(m[1]);
        s.title = part;
        out.appendChild(s);
      } else out.appendChild(document.createTextNode(part));
    }
  }
  $("test").addEventListener("input", renderPreview);
})();
