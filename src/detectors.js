/*
 * Detection engine. Runs in the page (MAIN world), the content-script world,
 * the popup, and Node tests.
 * Exposes globalThis.PromptRedaction = { SECTIONS, DETECTORS, createContext, redact, shortName }.
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

  // Same secret -> same placeholder for the whole page session.
  function createContext() {
    return { map: new Map(), counters: Object.create(null) };
  }

  function placeholderFor(ctx, type, value) {
    const key = type + "\u0000" + value;
    let ph = ctx.map.get(key);
    if (!ph) {
      ctx.counters[type] = (ctx.counters[type] || 0) + 1;
      ph = "[REDACTED_" + type + "_" + ctx.counters[type] + "]";
      ctx.map.set(key, ph);
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

  /**
   * @returns {{text: string, findings: Object<string, number>,
   *            matches: Array<{id: string, value: string, placeholder: string}>}}
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
    if (terms.length) {
      const re = new RegExp(
        terms
          .map(escapeRegex)
          .sort((a, b) => b.length - a.length)
          .join("|"),
        "gi",
      );
      out = out.replace(re, (m) => record("CUSTOM", m));
    }

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
    return { text: out, findings, matches };
  }

  root.PromptRedaction = {
    SECTIONS,
    DETECTORS,
    createContext,
    redact,
    shortName,
    _luhn: luhn,
    _verhoeff: verhoeff,
  };
  if (typeof module !== "undefined" && module.exports)
    module.exports = root.PromptRedaction;
})(typeof globalThis !== "undefined" ? globalThis : this);
