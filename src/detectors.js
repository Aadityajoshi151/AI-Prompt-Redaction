/*
 * Detection engine. Runs in the page (MAIN world), the content-script world,
 * the popup, and Node tests.
 * Exposes globalThis.PromptRedaction = { SECTIONS, DETECTORS, createContext, loadKey, redact,
 * shortName, summarize, categories, PLACEHOLDER_SOURCE }.
 *
 * A detector with `capture: n` must have its regex fully covered by capture
 * groups (lookarounds aside); only group n is replaced, the rest is kept.
 * Array order is run order: specific patterns run before generic ones.
 */
(function (root) {
  "use strict";

  // ---------- validators ----------
  function luhn(str) {
    const digits = str.replace(/\D/g, "");
    if (digits.length < 13 || digits.length > 19) return false;
    let sum = 0,
      dbl = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let d = digits.charCodeAt(i) - 48;
      if (dbl) {
        d *= 2;
        if (d > 9) d -= 9;
      }
      sum += d;
      dbl = !dbl;
    }
    return sum % 10 === 0;
  }

  // Verhoeff checksum (Aadhaar)
  const V_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
  ];
  const V_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
  ];
  function verhoeff(str) {
    const rev = str.replace(/\D/g, "").split("").reverse();
    let c = 0;
    for (let i = 0; i < rev.length; i++) c = V_D[c][V_P[i % 8][+rev[i]]];
    return c === 0;
  }

  function shannon(s) {
    const freq = {};
    for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
    let h = 0;
    for (const k in freq) {
      const p = freq[k] / s.length;
      h -= p * Math.log2(p);
    }
    return h;
  }

  function isIPv6(s) {
    if (!/\d/.test(s)) return false;
    if (s === "::" || s === "::1") return false;
    const dbl = s.split("::").length - 1;
    if (dbl > 1) return false;
    if (/^:[^:]/.test(s) || /[^:]:$/.test(s)) return false;
    const parts = s.split(":").filter((p) => p !== "");
    if (parts.some((p) => p.length > 4)) return false;
    return dbl === 0
      ? parts.length === 8
      : parts.length >= 1 && parts.length <= 7;
  }

  function isIPv4Worth(s) {
    return !/^(?:0\.0\.0\.0|127\.|255\.)/.test(s);
  }

  const notAllSame = (s) => !/^(\d)\1+$/.test(s.replace(/\D/g, ""));

  // Values that are references or placeholders, not real secrets
  const SECRET_REFERENCE =
    /^(?:process\.env|import\.meta\.env|os\.environ|os\.getenv|getenv|env[.(\[]|ENV\[|System\.getenv|\$|<|\{\{|%\(|config\.|settings\.|self\.|this\.|secrets\.|vault:|your[_-]|true$|false$|null$|none$|undefined$|\*+$|x+$|\.\.\.)/i;

  const SKIP_USERNAMES = new Set([
    "shared",
    "public",
    "default",
    "runner",
    "ubuntu",
    "ec2-user",
    "node",
    "app",
    "user",
    "username",
    "me",
    "you",
    "yourname",
    "your-name",
    "your_name",
    "name",
  ]);

  // ---------- sections (for the popup) ----------
  const SECTIONS = [
    {
      id: "personal",
      title: "Personal information",
      description: "Identity numbers, contact details and financial data.",
      subsections: [
        { id: "contact", title: "Contact details" },
        { id: "ids", title: "Government IDs" },
        { id: "financial", title: "Financial" },
      ],
    },
    {
      id: "code",
      title: "Code and technical",
      description: "For pasted code, configs, logs and terminal output.",
      subsections: [
        { id: "keys", title: "Keys and tokens" },
        { id: "config", title: "Config, headers and commands" },
        { id: "network", title: "Network and infrastructure" },
      ],
    },
  ];

  // ---------- detectors (array order = run order) ----------
  const DETECTORS = [
    // ===== Code: keys and tokens =====
    {
      id: "PRIVATE_KEY",
      section: "code",
      sub: "keys",
      label: "Private keys",
      hint: "-----BEGIN … PRIVATE KEY-----",
      short: "private key",
      defaultOn: true,
      regex:
        /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----/g,
    },
    {
      id: "AWS_ACCESS_KEY",
      section: "code",
      sub: "keys",
      label: "AWS access key IDs",
      hint: "AKIA…",
      short: "AWS key",
      defaultOn: true,
      regex: /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g,
    },
    {
      id: "AWS_SECRET_KEY",
      section: "code",
      sub: "keys",
      label: "AWS secret keys",
      hint: "aws_secret_access_key = …",
      short: "AWS secret",
      defaultOn: true,
      regex:
        /(aws_?secret_?(?:access_?)?key["']?\s*[:=]\s*["']?)([A-Za-z0-9/+=]{40})/gi,
      capture: 2,
    },
    {
      id: "ANTHROPIC_KEY",
      section: "code",
      sub: "keys",
      label: "Anthropic API keys",
      hint: "sk-ant-…",
      short: "Anthropic key",
      defaultOn: true,
      regex: /\bsk-ant-[A-Za-z0-9_-]{20,}/g,
    },
    {
      id: "OPENAI_KEY",
      section: "code",
      sub: "keys",
      label: "OpenAI API keys",
      hint: "sk-proj-…",
      short: "OpenAI key",
      defaultOn: true,
      regex: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g,
    },
    {
      id: "GITHUB_TOKEN",
      section: "code",
      sub: "keys",
      label: "GitHub tokens",
      hint: "ghp_…, github_pat_…",
      short: "GitHub token",
      defaultOn: true,
      regex:
        /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g,
    },
    {
      id: "STRIPE_KEY",
      section: "code",
      sub: "keys",
      label: "Stripe secret keys",
      hint: "sk_live_…",
      short: "Stripe key",
      defaultOn: true,
      regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
    },
    {
      id: "SLACK_TOKEN",
      section: "code",
      sub: "keys",
      label: "Slack tokens",
      hint: "xoxb-…",
      short: "Slack token",
      defaultOn: true,
      regex: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g,
    },
    {
      id: "GOOGLE_API_KEY",
      section: "code",
      sub: "keys",
      label: "Google / Firebase API keys",
      hint: "AIza…",
      short: "Google key",
      defaultOn: true,
      regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    },
    {
      id: "SERVICE_TOKEN",
      section: "code",
      sub: "keys",
      label: "Other service tokens",
      hint: "npm, PyPI, GitLab, Hugging Face, SendGrid, Twilio, Shopify, DigitalOcean, Telegram",
      short: "service token",
      defaultOn: true,
      regex:
        /\b(?:npm_[A-Za-z0-9]{36}|pypi-AgE[A-Za-z0-9_-]{50,}|glpat-[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{30,}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}|SK[0-9a-fA-F]{32}|shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}|dop_v1_[a-f0-9]{64}|\d{8,10}:AA[A-Za-z0-9_-]{33})\b/g,
    },
    {
      id: "AZURE_KEY",
      section: "code",
      sub: "keys",
      label: "Azure connection string keys",
      hint: "AccountKey=…, SharedAccessKey=…",
      short: "Azure key",
      defaultOn: true,
      regex:
        /((?:AccountKey|SharedAccessKey|SharedAccessSignature)\s*=\s*)([^;"'\s]{20,})/g,
      capture: 2,
    },
    {
      id: "WEBHOOK_URL",
      section: "code",
      sub: "keys",
      label: "Webhook URLs",
      hint: "Slack, Discord, Teams",
      short: "webhook URL",
      defaultOn: true,
      regex:
        /https:\/\/(?:hooks\.slack\.com\/services|discord(?:app)?\.com\/api\/webhooks|[a-z0-9-]+\.webhook\.office\.com\/webhookb2)\/[A-Za-z0-9/_@.-]+/g,
    },
    {
      id: "JWT",
      section: "code",
      sub: "keys",
      label: "JSON Web Tokens",
      hint: "eyJ….eyJ….…",
      short: "JWT",
      defaultOn: true,
      regex: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
    },

    // ===== Code: config, headers and commands =====
    {
      id: "URL_CREDENTIALS",
      section: "code",
      sub: "config",
      label: "Passwords in URLs",
      hint: "postgres://user:pass@host",
      short: "URL password",
      defaultOn: true,
      regex: /(\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:)([^\s@/]+)(@)/gi,
      capture: 2,
    },
    {
      id: "URL_QUERY_SECRET",
      section: "code",
      sub: "config",
      label: "Secrets in URL parameters",
      hint: "?token=…, &sig=…, X-Amz-Signature",
      short: "URL secret",
      defaultOn: true,
      regex:
        /([?&](?:access_token|refresh_token|id_token|token|api_key|apikey|key|client_secret|secret|password|sig|signature|auth|code|x-amz-signature|x-amz-credential|x-amz-security-token|x-goog-signature)=)([^&#\s"'<>]{6,})/gi,
      capture: 2,
    },
    {
      id: "SECRET_ASSIGNMENT",
      section: "code",
      sub: "config",
      label: "Secret values in configs and .env files",
      hint: 'DB_PASSWORD=…, "apiKey": "…"',
      short: "secret value",
      defaultOn: true,
      regex:
        /((?<![A-Za-z0-9])(?:[A-Za-z0-9]*[_-])?(?:password|passwd|pass|secret|token|api[_-]?key|apikey|private[_-]?key|credentials?|dsn|salt|signing[_-]?key|encryption[_-]?key)["']?\s*[:=]\s*["']?)([^\s"',;]{6,})/gi,
      capture: 2,
      validate: (v) => !SECRET_REFERENCE.test(v) && v.indexOf("(") === -1,
    },
    {
      id: "AUTH_HEADER",
      section: "code",
      sub: "config",
      label: "Authorization headers",
      hint: "Bearer …, Basic …",
      short: "auth token",
      defaultOn: true,
      regex: /(\b(?:[Bb]earer|Basic|Token)\s+)([A-Za-z0-9._~+/-]{16,}={0,2})/g,
      capture: 2,
    },
    {
      id: "COOKIE_HEADER",
      section: "code",
      sub: "config",
      label: "Cookie headers",
      hint: "Cookie: session=…",
      short: "cookie",
      defaultOn: true,
      regex: /(\b(?:Set-)?Cookie["']?\s*:\s*["']?)([^\r\n"']{8,})/gi,
      capture: 2,
    },
    {
      id: "CURL_USER",
      section: "code",
      sub: "config",
      label: "Passwords in curl commands",
      hint: "curl -u user:pass",
      short: "curl password",
      defaultOn: true,
      regex: /((?:^|\s)(?:-u|--user)\s+["']?[^:\s"']+:)([^\s"']+)/gm,
      capture: 2,
    },
    {
      id: "HIGH_ENTROPY",
      section: "code",
      sub: "config",
      label: "Random-looking strings",
      hint: "Catches unknown key formats; may flag hashes",
      short: "random string",
      defaultOn: false,
      regex: /\b[A-Za-z0-9+/_-]{32,}={0,2}/g,
      validate: (m) =>
        /[a-z]/.test(m) && /[A-Z]/.test(m) && /\d/.test(m) && shannon(m) > 4.2,
    },

    // ===== Code: network and infrastructure =====
    {
      id: "MAC_ADDRESS",
      section: "code",
      sub: "network",
      label: "MAC addresses",
      hint: "3c:22:fb:9a:10:4e",
      short: "MAC address",
      defaultOn: true,
      regex:
        /(?<![\w:.-])[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4}(?![\w:-])/g,
      validate: (m) => !/^(?:00[:-]){5}00$|^(?:ff[:-]){5}ff$/i.test(m),
    },
    {
      id: "IPV6",
      section: "code",
      sub: "network",
      label: "IPv6 addresses",
      hint: "2001:db8::8a2e:370:7334 (skips ::1)",
      short: "IPv6",
      defaultOn: true,
      regex: /(?<![\w:./])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])/g,
      validate: isIPv6,
    },
    {
      id: "IPV4",
      section: "code",
      sub: "network",
      label: "IPv4 addresses",
      hint: "10.0.12.7 (skips 127.x, 0.0.0.0)",
      short: "IPv4",
      defaultOn: true,
      regex:
        /(?<![\w.:-])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\w-]|\.\d)/g,
      validate: isIPv4Worth,
    },
    {
      id: "INTERNAL_HOST",
      section: "code",
      sub: "network",
      label: "Internal hostnames",
      hint: "db.prod.internal, *.corp, *.cluster.local",
      short: "internal host",
      defaultOn: true,
      regex:
        /\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:internal|corp|lan|intranet|localdomain|cluster\.local|home\.arpa)\b/gi,
    },
    {
      id: "PATH_USERNAME",
      section: "code",
      sub: "network",
      label: "Usernames in file paths",
      hint: "/home/jane/…, C:\\Users\\jane\\…",
      short: "username",
      defaultOn: true,
      regex:
        /((?<![\w.~/])\/(?:home|Users)\/|(?<![\w])[A-Za-z]:(?:\\{1,2}|\/)(?:Users|Documents and Settings)(?:\\{1,2}|\/))([A-Za-z0-9._-]+)/g,
      capture: 2,
      validate: (u) => !SKIP_USERNAMES.has(u.toLowerCase()),
    },
    {
      id: "AWS_ACCOUNT_ID",
      section: "code",
      sub: "network",
      label: "AWS account IDs in ARNs",
      hint: "arn:aws:iam::123456789012:…",
      short: "AWS account",
      defaultOn: true,
      regex: /(arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:)(\d{12})(?=:)/g,
      capture: 2,
    },

    // ===== Personal: financial (run before other digit patterns) =====
    {
      id: "BANK_ACCOUNT",
      section: "personal",
      sub: "financial",
      label: "Bank account numbers",
      hint: "When labelled: A/C No. 0123…",
      short: "bank account",
      defaultOn: true,
      regex:
        /(\b(?:a\/c|acct|account)\.?(?:\s*(?:no|number|num)\.?)?\s*[:#-]?\s*)(\d{9,18})\b/gi,
      capture: 2,
    },
    {
      id: "CREDIT_CARD",
      section: "personal",
      sub: "financial",
      label: "Card numbers",
      hint: "Checked with the Luhn checksum",
      short: "card number",
      defaultOn: true,
      regex: /\b\d(?:[ -]?\d){12,18}\b/g,
      validate: luhn,
    },
    {
      id: "IBAN",
      section: "personal",
      sub: "financial",
      label: "IBANs",
      hint: "GB82 WEST 1234 …",
      short: "IBAN",
      defaultOn: true,
      regex: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?\b/g,
    },

    // ===== Personal: government IDs =====
    {
      id: "AADHAAR",
      section: "personal",
      sub: "ids",
      label: "Aadhaar numbers",
      hint: "Checked with the Verhoeff checksum",
      short: "Aadhaar",
      defaultOn: true,
      regex: /\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b/g,
      validate: verhoeff,
    },
    {
      id: "GSTIN",
      section: "personal",
      sub: "ids",
      label: "GSTINs",
      hint: "27ABCDE1234F1Z5",
      short: "GSTIN",
      defaultOn: true,
      regex: /\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b/g,
    },
    {
      id: "PAN",
      section: "personal",
      sub: "ids",
      label: "PAN numbers",
      hint: "ABCPE1234F",
      short: "PAN",
      defaultOn: true,
      regex: /\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b/g,
    },
    {
      id: "VOTER_ID",
      section: "personal",
      sub: "ids",
      label: "Voter IDs (EPIC)",
      hint: "ABC1234567; may flag order codes",
      short: "voter ID",
      defaultOn: false,
      regex: /\b[A-Z]{3}\d{7}\b/g,
    },
    {
      id: "PASSPORT_IN",
      section: "personal",
      sub: "ids",
      label: "Indian passport numbers",
      hint: "A1234567; may flag other codes",
      short: "passport",
      defaultOn: false,
      regex: /\b[A-PR-WY][1-9]\d{6}\b/g,
    },
    {
      id: "US_SSN",
      section: "personal",
      sub: "ids",
      label: "US Social Security numbers",
      hint: "123-45-6789",
      short: "SSN",
      defaultOn: true,
      regex: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
    },

    // ===== Personal: contact details =====
    {
      id: "UPI_ID",
      section: "personal",
      sub: "contact",
      label: "UPI IDs",
      hint: "name@okaxis, 98…@ybl",
      short: "UPI ID",
      defaultOn: true,
      regex:
        /\b[A-Za-z0-9._-]{2,256}@(?:ok(?:axis|hdfcbank|icici|sbi)|ybl|ibl|axl|paytm|pt(?:yes|axis|hdfc|sbi)|upi|apl|yapl|fbl|jupiteraxis|slc|freecharge|airtel|axisbank|icici|sbi|hdfcbank|kotak|indus|pnb|boi|barodampay|abfspay|wa(?:icici|hdfcbank|axis|sbi)|ikwik|naviaxis|superyes|kbaxis)\b(?!\.)/gi,
    },
    {
      id: "EMAIL",
      section: "personal",
      sub: "contact",
      label: "Email addresses",
      hint: "jane@company.com",
      short: "email",
      defaultOn: true,
      regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    },
    {
      id: "PHONE_INTL",
      section: "personal",
      sub: "contact",
      label: "Phone numbers with country code",
      hint: "+91 99999 99999, +1 (555) 123-4567",
      short: "phone",
      defaultOn: true,
      regex: /(?<![\w+])\+\d{1,3}(?:[\s-]?\(?\d{1,5}\)?){2,5}(?!\w)/g,
      validate: (m) => {
        const n = m.replace(/\D/g, "").length;
        return n >= 8 && n <= 15;
      },
    },
    {
      id: "IN_MOBILE",
      section: "personal",
      sub: "contact",
      label: "Indian mobile numbers",
      hint: "99999 99999, 09876543210",
      short: "mobile",
      defaultOn: true,
      regex: /(?<![\w.+/-])0?[6-9]\d{4}[\s-]?\d{5}(?![\w/-])(?!\.\d)/g,
      validate: notAllSame,
    },
  ];

  const SHORT = { CUSTOM: "custom term" };
  for (const d of DETECTORS) SHORT[d.id] = d.short;
  const shortName = (id) => SHORT[id] || id.toLowerCase().replace(/_/g, " ");

  // Wording shared by the on-page UI and the popup preview.
  // "bank account, email ×2 · 1 also matched: mobile". Each item counts once,
  // under the category that named its placeholder; other matches are extra info.
  function summarize(findings, matches) {
    const main = Object.entries(findings)
      .map(([id, n]) => shortName(id) + (n > 1 ? " \u00d7" + n : ""))
      .join(", ");
    const multi = matches.filter((m) => m.also && m.also.length);
    if (!multi.length) return main;
    const also = [...new Set(multi.flatMap((m) => m.also))].map(shortName).join(", ");
    return main + " \u00b7 " + multi.length + " also matched: " + also;
  }
  // "bank account (also matches: mobile)"
  function categories(m) {
    const also = m.also && m.also.length ? " (also matches: " + m.also.map(shortName).join(", ") + ")" : "";
    return shortName(m.id) + also;
  }

  // ---------- placeholder tags ----------
  // A placeholder is [REDACTED_<TYPE>_<tag>]. The tag is the first 6 hex
  // characters of HMAC-SHA-256(key, value), so the same value gets the same
  // placeholder in every chat and after a reload or restart, without storing
  // any values. The key is random, made once per browser (see loadKey), and
  // never leaves it: without the key a tag says nothing about the value.
  // SHA-256 is implemented here because redact() is synchronous and shared by
  // the page, the popup and the Node tests; crypto.subtle is async.
  const TAG_LENGTH = 6;
  const SHA_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));

  function sha256(bytes) {
    const h = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    const len = bytes.length;
    const total = Math.ceil((len + 9) / 64) * 64;
    const msg = new Uint8Array(total);
    msg.set(bytes);
    msg[len] = 0x80;
    const view = new DataView(msg.buffer);
    view.setUint32(total - 8, Math.floor(len / 0x20000000));
    view.setUint32(total - 4, (len * 8) >>> 0);
    const w = new Uint32Array(64);
    for (let off = 0; off < total; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const x = w[i - 15], y = w[i - 2];
        w[i] = w[i - 16] + (rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3)) + w[i - 7] + (rotr(y, 17) ^ rotr(y, 19) ^ (y >>> 10));
      }
      let a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
      for (let i = 0; i < 64; i++) {
        const t1 = (k + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + SHA_K[i] + w[i]) >>> 0;
        const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
        k = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += k;
    }
    const out = new Uint8Array(32);
    const outView = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) outView.setUint32(i * 4, h[i]);
    return out;
  }

  function hmacSha256(key, message) {
    if (key.length > 64) key = sha256(key);
    const inner = new Uint8Array(64 + message.length), outer = new Uint8Array(64 + 32);
    for (let i = 0; i < 64; i++) {
      const k = i < key.length ? key[i] : 0;
      inner[i] = k ^ 0x36;
      outer[i] = k ^ 0x5c;
    }
    inner.set(message, 64);
    outer.set(sha256(inner), 64);
    return sha256(outer);
  }

  // UTF-8 without TextEncoder (jsdom, used by the tests, doesn't provide it).
  function utf8Bytes(str) {
    const out = [];
    for (let i = 0; i < str.length; i++) {
      let c = str.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
        const next = str.charCodeAt(i + 1);
        if (next >= 0xdc00 && next <= 0xdfff) { c = 0x10000 + ((c - 0xd800) << 10) + (next - 0xdc00); i++; }
      }
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
      else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
      else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
    return new Uint8Array(out);
  }

  const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  const KEY_FORMAT = /^[0-9a-f]{64}$/;

  // A new random key, as 64 hex characters.
  function randomKey() {
    const bytes = new Uint8Array(32);
    if (root.crypto && root.crypto.getRandomValues) root.crypto.getRandomValues(bytes);
    else for (let i = 0; i < 32; i++) bytes[i] = Math.floor(Math.random() * 256);
    return toHex(bytes);
  }

  // The browser's saved key, created on first use. `area` is the extension's
  // storage.local, which isn't synced to the browser account.
  async function loadKey(area) {
    const stored = (await area.get("tagKey")).tagKey;
    if (KEY_FORMAT.test(stored)) return stored;
    const key = randomKey();
    await area.set({ tagKey: key });
    return key;
  }

  // Holds the key and remembers placeholders already worked out. Without a
  // valid key it uses a random one: placeholders are then consistent only
  // within this context, but never computed without a key.
  function createContext(key) {
    const hex = KEY_FORMAT.test(key) ? key : randomKey();
    return { key: new Uint8Array(hex.match(/../g).map((b) => parseInt(b, 16))), map: new Map() };
  }

  // The tag depends on the value only, not the type: a number redacted as a
  // bank account in one message and as a mobile in another keeps its tag.
  function placeholderFor(ctx, type, value) {
    const id = type + "\u0000" + value;
    let ph = ctx.map.get(id);
    if (!ph) {
      const tag = toHex(hmacSha256(ctx.key, utf8Bytes(value))).slice(0, TAG_LENGTH);
      ph = "[REDACTED_" + type + "_" + tag + "]";
      ctx.map.set(id, ph);
    }
    return ph;
  }

  function escapeRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function isEnabled(det, overrides) {
    return overrides && typeof overrides[det.id] === "boolean"
      ? overrides[det.id]
      : det.defaultOn;
  }

  // For the UI: matches one placeholder and captures its type.
  const PLACEHOLDER_SOURCE = "\\[REDACTED_([A-Z0-9_]+?)_[0-9a-f]{" + TAG_LENGTH + "}\\]";
  const PLACEHOLDER = /\[REDACTED_[A-Z0-9_]+?_[0-9a-f]{6}\]/;
  const PLACEHOLDER_ONLY = /^\[REDACTED_[A-Z0-9_]+?_[0-9a-f]{6}\]$/i;

  // Copies of detector regexes with the `d` flag, for match positions.
  const INDEXED = new Map();
  function indexed(det) {
    let re = INDEXED.get(det.id);
    if (!re) INDEXED.set(det.id, (re = new RegExp(det.regex.source, det.regex.flags + "d")));
    return re;
  }

  // Every match of every enabled detector in the original text, as spans.
  // Read-only: used to place custom terms and to find the other categories a
  // redacted value falls into.
  function detectorSpans(text, overrides) {
    const spans = [];
    for (const det of DETECTORS) {
      if (!isEnabled(det, overrides)) continue;
      const g = det.capture || 0;
      for (const m of text.matchAll(indexed(det))) {
        const secret = m[g];
        if (!secret || secret.indexOf("REDACTED_") !== -1) continue;
        if (det.validate && !det.validate(secret)) continue;
        spans.push({ id: det.id, value: secret, start: m.indices[g][0], end: m.indices[g][1] });
      }
    }
    return spans;
  }

  // For each redacted value, the other detectors whose whole match lies inside
  // it. Wider overlapping matches are left out: the part outside the redacted
  // value was sent, so "also matches" would overstate what was hidden.
  function addAlso(matches, spans) {
    const order = (id) => (id === "CUSTOM" ? -1 : DETECTORS.findIndex((d) => d.id === id));
    for (const m of matches) {
      const also = new Set();
      for (const own of spans) {
        if (own.id !== m.id || own.value !== m.value) continue;
        for (const o of spans) {
          if (o.id !== m.id && o.start >= own.start && o.end <= own.end) also.add(o.id);
        }
      }
      m.also = [...also].sort((a, b) => order(a) - order(b));
    }
  }

  /**
   * Detectors run in array order; the first to match a value names its
   * placeholder. `also` lists the other categories the value falls into.
   * @returns {{text: string, findings: Object<string, number>,
   *            matches: Array<{id: string, value: string, placeholder: string, also: string[]}>}}
   */
  function redact(text, opts) {
    opts = opts || {};
    const ctx = opts.ctx || createContext();
    const findings = {};
    const matches = [];
    if (typeof text !== "string" || !text) return { text, findings, matches };

    const record = (id, value) => {
      findings[id] = (findings[id] || 0) + 1;
      const placeholder = placeholderFor(
        ctx,
        id,
        id === "CUSTOM" ? value.toLowerCase() : value,
      );
      matches.push({ id, value, placeholder });
      return placeholder;
    };
    let out = text;

    const terms = (opts.customTerms || [])
      .map((t) => t.trim())
      .filter((t) => t.length >= 2);
    const termsSource = terms
      .map(escapeRegex)
      .sort((a, b) => b.length - a.length)
      .join("|");
    const spans = [];
    let customRe = null;
    if (terms.length) {
      // Placeholders are matched first and kept, so a term like "email" can't
      // break an existing [REDACTED_EMAIL_a3f9c1].
      customRe = new RegExp(PLACEHOLDER.source + "|" + termsSource, "gi");
      for (const m of text.matchAll(new RegExp(termsSource, "gi"))) {
        spans.push({ id: "CUSTOM", value: m[0], start: m.index, end: m.index + m[0].length });
      }
    }
    const detSpans = spans.length ? detectorSpans(text, opts.overrides) : null;
    // A custom term inside a larger detected value (acme in jane@acme.com) is
    // left for that detector, so the whole value is hidden, not just the term.
    const insideDetected = (start, end) =>
      detSpans.some((s) => s.start <= start && end <= s.end && s.end - s.start > end - start);
    const customPass = (fromOriginal) => (m, offset) => {
      if (PLACEHOLDER_ONLY.test(m)) return m;
      if (fromOriginal && insideDetected(offset, offset + m.length)) return m;
      return record("CUSTOM", m);
    };
    if (customRe) out = out.replace(customRe, customPass(true));

    for (const det of DETECTORS) {
      if (!isEnabled(det, opts.overrides)) continue;
      det.regex.lastIndex = 0;
      out = out.replace(det.regex, function (match) {
        const groups = Array.prototype.slice.call(
          arguments,
          1,
          arguments.length - 2,
        );
        const secret = det.capture ? groups[det.capture - 1] : match;
        if (!secret || secret.indexOf("REDACTED_") !== -1) return match;
        if (det.validate && !det.validate(secret)) return match;
        const ph = record(det.id, secret);
        if (!det.capture) return ph;
        return groups
          .map((g, i) => (i === det.capture - 1 ? ph : g || ""))
          .join("");
      });
    }
    // Anything left of a custom term (a detector didn't cover it after all).
    if (customRe) out = out.replace(customRe, customPass(false));
    if (matches.length) addAlso(matches, spans.concat(detSpans || detectorSpans(text, opts.overrides)));
    return { text: out, findings, matches };
  }

  root.PromptRedaction = {
    SECTIONS,
    DETECTORS,
    createContext,
    loadKey,
    PLACEHOLDER_SOURCE,
    redact,
    shortName,
    summarize,
    categories,
    _hmacSha256: hmacSha256,
    _luhn: luhn,
    _verhoeff: verhoeff,
  };
  if (typeof module !== "undefined" && module.exports)
    module.exports = root.PromptRedaction;
})(typeof globalThis !== "undefined" ? globalThis : this);
