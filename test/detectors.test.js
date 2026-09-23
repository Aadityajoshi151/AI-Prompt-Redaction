// Run with: node test/detectors.test.js
const assert = require("assert");
const R = require("../src/detectors.js");

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); pass++; console.log("  ok   " + name); }
  catch (e) { fail++; console.log("  FAIL " + name + "\n       " + e.message.split("\n").join("\n       ")); }
}
const red = (s, o) => R.redact(s, o).text;
const hits = (s, o) => R.redact(s, o).findings;
const only = (s, id, o) => assert.deepStrictEqual(Object.keys(hits(s, o)), [id], JSON.stringify(hits(s, o)));
const none = (s, o) => assert.deepStrictEqual(hits(s, o), {});

console.log("Structure");
t("every detector belongs to a known section and subsection", () => {
  for (const d of R.DETECTORS) {
    const sec = R.SECTIONS.find((s) => s.id === d.section);
    assert.ok(sec, d.id + " section");
    assert.ok(sec.subsections.find((s) => s.id === d.sub), d.id + " subsection");
    assert.ok(d.label && d.short, d.id + " labels");
  }
});
t("ids are unique", () => assert.strictEqual(new Set(R.DETECTORS.map((d) => d.id)).size, R.DETECTORS.length));

console.log("Code: keys and tokens");
t("AWS access key", () => only("key AKIAIOSFODNN7EXAMPLE here", "AWS_ACCESS_KEY"));
t("AWS secret keeps prefix", () => assert.strictEqual(
  red("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
  "aws_secret_access_key = [REDACTED_AWS_SECRET_KEY_1]"));
t("Anthropic key", () => only("sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123", "ANTHROPIC_KEY"));
t("OpenAI key", () => only("sk-proj-abcdefghijklmnopqrstuvwxyz0123", "OPENAI_KEY"));
t("GitHub PAT", () => only("ghp_" + "a1".repeat(18), "GITHUB_TOKEN"));
t("Stripe", () => only("sk_live_4eC39HqLyjWDarjtT1zdp7dc", "STRIPE_KEY"));
t("Google key", () => only("AIzaSyA-1234567890abcdefghijklmnopqrstu", "GOOGLE_API_KEY"));
t("npm token", () => only("//registry.npmjs.org/:_authToken=npm_" + "Ab1".repeat(12), "SERVICE_TOKEN"));
t("Hugging Face token", () => only("HF: hf_" + "aB3".repeat(11), "SERVICE_TOKEN"));
t("GitLab token", () => only("glpat-xxxxYYYYzzzz11112222", "SERVICE_TOKEN"));
t("SendGrid key", () => only("SG." + "a".repeat(22) + "." + "b".repeat(43), "SERVICE_TOKEN"));
t("Telegram bot token", () => only("bot 123456789:AA" + "h".repeat(33), "SERVICE_TOKEN"));
t("Azure AccountKey keeps rest of string", () => assert.strictEqual(
  red("DefaultEndpointsProtocol=https;AccountName=acme;AccountKey=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA==;EndpointSuffix=core.windows.net"),
  "DefaultEndpointsProtocol=https;AccountName=acme;AccountKey=[REDACTED_AZURE_KEY_1];EndpointSuffix=core.windows.net"));
t("Discord webhook", () => only("https://discord.com/api/webhooks/123456/abcDEF-ghi_jkl", "WEBHOOK_URL"));
t("JWT", () => only("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "JWT"));
t("PEM block", () => assert.strictEqual(
  red("-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn\n-----END OPENSSH PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY_1]"));

console.log("Code: config, headers and commands");
t("DB URL password only", () => assert.strictEqual(
  red("postgres://admin:hunter22@db.example.com:5432/app"),
  "postgres://admin:[REDACTED_URL_CREDENTIALS_1]@db.example.com:5432/app"));
t(".env DB_PASSWORD", () => assert.strictEqual(red('DB_PASSWORD="s3cr3tPass!"'), 'DB_PASSWORD="[REDACTED_SECRET_ASSIGNMENT_1]"'));
t(".env GITHUB_TOKEN style", () => only("MY_SERVICE_TOKEN=abc123xyz789", "SECRET_ASSIGNMENT"));
t("JSON apiKey", () => only('{ "apiKey": "live-9f8e7d6c5b" }', "SECRET_ASSIGNMENT"));
t("YAML password", () => only("  password: Tr0ub4dor&3", "SECRET_ASSIGNMENT"));
t("skips process.env reference", () => none("const apiKey = process.env.API_KEY;"));
t("skips os.environ / ${VAR} / function calls", () => {
  none('password = os.environ["DB_PASS"]');
  none("token: ${{ secrets.GITHUB_TOKEN }}");
  none("DB_PASSWORD=${DB_PASSWORD}");
  none("token = get_token(user)");
});
t("skips prose and counters", () => { none("max_tokens=1000"); none("Enter your password: "); none("bypass=enabled"); });
t("URL query token", () => assert.strictEqual(
  red("GET https://api.x.com/v1/data?limit=10&access_token=abcdef123456&page=2"),
  "GET https://api.x.com/v1/data?limit=10&access_token=[REDACTED_URL_QUERY_SECRET_1]&page=2"));
t("S3 presigned signature", () => assert.ok(hits("https://b.s3.amazonaws.com/f?X-Amz-Signature=abcdef0123456789").URL_QUERY_SECRET));
t("Bearer header", () => assert.strictEqual(
  red("Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456"), "Authorization: Bearer [REDACTED_AUTH_HEADER_1]"));
t("Basic header", () => only("-H 'Authorization: Basic dXNlcjpwYXNzd29yZDEyMw=='", "AUTH_HEADER"));
t("Cookie header", () => assert.strictEqual(
  red("Cookie: sessionid=abc123; csrftoken=xyz789"), "Cookie: [REDACTED_COOKIE_HEADER_1]"));
t("curl -u", () => assert.strictEqual(
  red("curl -u admin:hunter22 https://example.com"), "curl -u admin:[REDACTED_CURL_USER_1] https://example.com"));
t("no double redaction", () => only("api_key=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123", "ANTHROPIC_KEY"));

console.log("Code: network and infrastructure");
t("IPv4", () => assert.strictEqual(red("ssh deploy@10.20.30.40 -p 22"), "ssh deploy@[REDACTED_IPV4_1] -p 22"));
t("IPv4 with port and CIDR", () => { only("http://192.168.1.15:8080/", "IPV4"); only("allow 172.16.0.0/12", "IPV4"); });
t("IPv4 skips loopback, 0.0.0.0, netmask", () => { none("listen 127.0.0.1:3000"); none("bind 0.0.0.0"); none("mask 255.255.255.0"); });
t("IPv4 skips version strings", () => { none("v1.2.3.4"); none("chrome 120.0.6099.109"); });
t("IPv6 full", () => only("addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334 up", "IPV6"));
t("IPv6 compressed", () => only("inet6 fe80::1ff:fe23:4567:890a/64", "IPV6"));
t("IPv6 skips ::1, times, C++ paths", () => {
  none("listen [::1]:8080"); none("at 12:30:45"); none("std::vector<int> a; foo::bar(); dead::beef");
});
t("MAC address", () => only("ether 3c:22:fb:9a:10:4e", "MAC_ADDRESS"));
t("MAC dash form", () => only("MAC 3C-22-FB-9A-10-4E", "MAC_ADDRESS"));
t("internal hostnames", () => {
  only("connect to db-01.prod.internal", "INTERNAL_HOST");
  only("http://api.payments.svc.cluster.local:80", "INTERNAL_HOST");
  only("ip-10-0-1-5.ec2.internal", "INTERNAL_HOST");
});
t("username in Linux/macOS path", () => assert.strictEqual(
  red("File \"/home/priya/app/main.py\", line 3"), "File \"/home/[REDACTED_PATH_USERNAME_1]/app/main.py\", line 3"));
t("username in Windows path (incl. JSON-escaped)", () => {
  assert.strictEqual(red("C:\\Users\\rahul.k\\Desktop"), "C:\\Users\\[REDACTED_PATH_USERNAME_1]\\Desktop");
  only('"C:\\\\Users\\\\rahul\\\\AppData"', "PATH_USERNAME");
});
t("path usernames: skips generic names and URLs", () => {
  none("/home/runner/work/repo"); none("/Users/Shared/x"); none("https://site.com/home/about");
});
t("AWS account in ARN", () => assert.strictEqual(
  red("arn:aws:iam::123456789012:role/Admin"), "arn:aws:iam::[REDACTED_AWS_ACCOUNT_ID_1]:role/Admin"));

console.log("Personal");
t("email", () => assert.strictEqual(red("mail jane.doe@corp.com now"), "mail [REDACTED_EMAIL_1] now"));
t("UPI", () => only("pay me at rahul99@okaxis", "UPI_ID"));
t("phone with country code", () => { only("call +91 98765 43210", "PHONE_INTL"); only("+1 (555) 123-4567", "PHONE_INTL"); });
t("Indian mobile", () => { only("call 9876543210", "IN_MOBILE"); only("ph 98765-43210", "IN_MOBILE"); only("09876543210", "IN_MOBILE"); });
t("Indian mobile skips 9999999999 and decimals", () => { none("MAX = 9999999999"); none("x = 9876543210.5"); });
t("card valid / invalid", () => { only("card 4111 1111 1111 1111", "CREDIT_CARD"); none("order 4111 1111 1111 1112"); });
t("bank account when labelled", () => assert.strictEqual(
  red("A/C No. 50100123456789"), "A/C No. [REDACTED_BANK_ACCOUNT_1]"));
t("Aadhaar Verhoeff", () => {
  let valid;
  for (let d = 0; d <= 9; d++) if (R._verhoeff("23456789012" + d)) valid = "23456789012" + d;
  only("id " + valid.replace(/(\d{4})(?=\d)/g, "$1 "), "AADHAAR");
  none("id " + valid.slice(0, 11) + ((+valid[11] + 1) % 10));
});
t("PAN", () => only("PAN: ABCPE1234F", "PAN"));
t("GSTIN (not double counted as PAN)", () => only("GSTIN 27ABCPE1234F1Z5", "GSTIN"));
t("voter ID and passport are opt-in", () => {
  none("EPIC ABC1234567"); only("EPIC ABC1234567", "VOTER_ID", { overrides: { VOTER_ID: true } });
  none("passport K1234567"); only("passport K1234567", "PASSPORT_IN", { overrides: { PASSPORT_IN: true } });
});
t("US SSN", () => only("ssn 123-45-6789", "US_SSN"));

console.log("Behaviour");
t("stable placeholders across calls", () => {
  const ctx = R.createContext();
  assert.strictEqual(red("a@b.com and c@d.com and a@b.com", { ctx }),
    "[REDACTED_EMAIL_1] and [REDACTED_EMAIL_2] and [REDACTED_EMAIL_1]");
  assert.strictEqual(red("again a@b.com", { ctx }), "again [REDACTED_EMAIL_1]");
});
t("matches report original values and placeholders", () => {
  const { matches } = R.redact("x a@b.com y 10.1.2.3");
  assert.deepStrictEqual(matches.map((m) => [m.id, m.value, m.placeholder]).sort(), [
    ["EMAIL", "a@b.com", "[REDACTED_EMAIL_1]"], ["IPV4", "10.1.2.3", "[REDACTED_IPV4_1]"]]);
});
t("custom terms", () => assert.strictEqual(
  red("Status of project falcon?", { customTerms: ["Project Falcon"] }), "Status of [REDACTED_CUSTOM_1]?"));
t("detector can be disabled", () => none("x@y.com", { overrides: { EMAIL: false } }));

console.log("False positives in ordinary code");
const clean = [
  "const id = '550e8400-e29b-41d4-a716-446655440000';",
  "git commit 9fceb02d0ae598e95dc970b74767f19372d61af8",
  "setTimeout(fn, 30000); retries = 3;",
  "Released 2024.10.15, see https://example.com/docs",
  "const ts = 1727078400000; // unix ms",
  "npm install react@18.3.1 lodash@4.17.21",
  "import { useState } from 'react';",
  "SELECT * FROM users WHERE id = 1234567890;",
  "for i in range(10): print(i)",
  "docker run -p 8080:80 nginx:1.25",
  "border: 1px solid #ccc; color: #1F2A2E;",
];
for (const s of clean) t("clean: " + s.slice(0, 44), () => none(s));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
