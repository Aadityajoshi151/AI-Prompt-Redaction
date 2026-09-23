/*
 * Copies the extension into build/chromium/ for Chrome, Edge and Brave.
 * The only difference from the Firefox build: the manifest has no
 * browser_specific_settings, which Chromium flags as an unrecognized key.
 */
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const out = path.join(root, "build", "chromium");
// Everything the extension needs at runtime. Keep in sync with manifest.json.
const FILES = ["LICENSE", "src", "popup", "icons"];

fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(out, { recursive: true });
for (const f of FILES) fs.cpSync(path.join(root, f), path.join(out, f), { recursive: true });

const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
delete manifest.browser_specific_settings;
fs.writeFileSync(path.join(out, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
