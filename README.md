<div align="center">

# AI Prompt Redaction (APR)

  <img src="icons/icon.svg" alt="AI Prompt Redaction icon" width="96" height="96">

</div>

A browser extension to redact secrets and sensitive data before they are sent to Claude.ai. All detection happens locally in your browser, and the extension doesn't collect any of your data.

> [!IMPORTANT]
>
> This project was built with AI assistance (Claude). The code,
> tests and documentation were largely written by AI, and every
> change is reviewed by me before it's merged.

## Features

- **Redacts before sending** - sensitive values are replaced with placeholders such as `[REDACTED_EMAIL_1]`.
- **Consistent placeholders** - the same value always gets the same placeholder, so the AI can still follow references to it.
- **Shows what it changed** - values are highlighted as you type, and stay marked in the chat after sending.
- **Custom terms** - add your own words to redact, such as client names or product names.
- **Try it** - preview in the popup what would be redacted.

## What it detects

### Personal information

| Category        | Detector                        | Example or note                    | On by default |
| --------------- | ------------------------------- | ---------------------------------- | :-----------: |
| Contact details | UPI IDs                         | name@okaxis, 98…@ybl               |      ✅       |
| Contact details | Email addresses                 | jane@company.com                   |      ✅       |
| Contact details | Phone numbers with country code | +91 99999 99999, +1 (555) 123-4567 |      ✅       |
| Contact details | Indian mobile numbers           | 99999 99999, 09876543210           |      ✅       |
| Government IDs  | Aadhaar numbers                 | Checked with the Verhoeff checksum |      ✅       |
| Government IDs  | GSTINs                          | 27ABCDE1234F1Z5                    |      ✅       |
| Government IDs  | PAN numbers                     | ABCPE1234F                         |      ✅       |
| Government IDs  | Voter IDs (EPIC)                | ABC1234567; may flag order codes   |      ❌       |
| Government IDs  | Indian passport numbers         | A1234567; may flag other codes     |      ❌       |
| Government IDs  | US Social Security numbers      | 123-45-6789                        |      ✅       |
| Financial       | Bank account numbers            | When labelled: A/C No. 0123…       |      ✅       |
| Financial       | Card numbers                    | Checked with the Luhn checksum     |      ✅       |
| Financial       | IBANs                           | GB82 WEST 1234 …                   |      ✅       |

### Code and technical

| Category                     | Detector                                | Example or note                                                                    | On by default |
| ---------------------------- | --------------------------------------- | ---------------------------------------------------------------------------------- | :-----------: |
| Keys and tokens              | Private keys                            | -----BEGIN … PRIVATE KEY-----                                                      |      ✅       |
| Keys and tokens              | AWS access key IDs                      | AKIA…                                                                              |      ✅       |
| Keys and tokens              | AWS secret keys                         | aws_secret_access_key = …                                                          |      ✅       |
| Keys and tokens              | Anthropic API keys                      | sk-ant-…                                                                           |      ✅       |
| Keys and tokens              | OpenAI API keys                         | sk-proj-…                                                                          |      ✅       |
| Keys and tokens              | GitHub tokens                           | `ghp_…`, `github_pat_…`                                                            |      ✅       |
| Keys and tokens              | Stripe secret keys                      | `sk_live_…`                                                                        |      ✅       |
| Keys and tokens              | Slack tokens                            | xoxb-…                                                                             |      ✅       |
| Keys and tokens              | Google / Firebase API keys              | AIza…                                                                              |      ✅       |
| Keys and tokens              | Other service tokens                    | npm, PyPI, GitLab, Hugging Face, SendGrid, Twilio, Shopify, DigitalOcean, Telegram |      ✅       |
| Keys and tokens              | Azure connection string keys            | AccountKey=…, SharedAccessKey=…                                                    |      ✅       |
| Keys and tokens              | Webhook URLs                            | Slack, Discord, Teams                                                              |      ✅       |
| Keys and tokens              | JSON Web Tokens                         | eyJ….eyJ….…                                                                        |      ✅       |
| Config, headers and commands | Passwords in URLs                       | postgres://user:pass@host                                                          |      ✅       |
| Config, headers and commands | Secrets in URL parameters               | ?token=…, &sig=…, X-Amz-Signature                                                  |      ✅       |
| Config, headers and commands | Secret values in configs and .env files | DB_PASSWORD=…, "apiKey": "…"                                                       |      ✅       |
| Config, headers and commands | Authorization headers                   | Bearer …, Basic …                                                                  |      ✅       |
| Config, headers and commands | Cookie headers                          | Cookie: session=…                                                                  |      ✅       |
| Config, headers and commands | Passwords in curl commands              | curl -u user:pass                                                                  |      ✅       |
| Config, headers and commands | Random-looking strings                  | Catches unknown key formats; may flag hashes                                       |      ❌       |
| Network and infrastructure   | MAC addresses                           | 3c:22:fb:9a:10:4e                                                                  |      ✅       |
| Network and infrastructure   | IPv6 addresses                          | 2001:db8::8a2e:370:7334 (skips ::1)                                                |      ✅       |
| Network and infrastructure   | IPv4 addresses                          | 10.0.12.7 (skips 127.x, 0.0.0.0)                                                   |      ✅       |
| Network and infrastructure   | Internal hostnames                      | db.prod.internal, \*.corp, \*.cluster.local                                        |      ✅       |
| Network and infrastructure   | Usernames in file paths                 | /home/jane/…, C:\Users\jane\…                                                      |      ✅       |
| Network and infrastructure   | AWS account IDs in ARNs                 | arn:aws:iam::123456789012:…                                                        |      ✅       |

The code detectors are tuned to leave ordinary code alone: UUIDs, git hashes, version numbers, timestamps, `127.0.0.1`, `process.env.X` and similar aren't redacted.

## Installation

### Firefox

Requires Firefox 140 or later.

An official listing on addons.mozilla.org is on its way. The link will be added here once it's approved.

### Chrome, Edge and Brave

Requires version 111 or later. The extension isn't published on the Chrome Web Store, so you load it yourself in developer mode:

1. Download `ai_prompt_redaction-<version>-chromium.zip` from the [latest release](https://github.com/Aadityajoshi151/AI-Prompt-Redaction/releases/latest).
2. Unzip it into a folder you'll keep. The browser loads the extension from this folder, so deleting or moving it removes the extension.
3. Open the extensions page:
   - Chrome: `chrome://extensions`
   - Edge: `edge://extensions`
   - Brave: `brave://extensions`
4. Turn on **Developer mode** (top right in Chrome and Brave, left sidebar in Edge).
5. Click **Load unpacked** and select the unzipped folder (the one that contains `manifest.json`).
6. Pin the extension to the toolbar for easy access to its settings.

Your browser may remind you that a developer-mode extension is installed. That's expected.

**Updating:** extensions loaded this way don't update automatically. Download the new zip, replace the contents of the same folder, then click the reload icon on the extension's card. Keeping the same folder keeps your settings.

## Usage

1. Open [claude.ai](https://claude.ai) and write a message as usual. Anything that will be redacted is highlighted as you type.
2. Send it. A toast confirms what was redacted, and the original values stay marked in your message.
3. Click the extension's toolbar icon to switch redaction on or off, choose detectors, add custom terms, or try out text.

## Permissions

- `storage` - saves your settings and a count of redacted items. Settings use the browser's sync storage, so they follow your browser account if you have sync turned on.
- Access to `claude.ai` - needed to scan messages before they're sent. In Firefox you can revoke this. If you do, the popup shows a button to grant it again.

## Limitations

- Only claude.ai is supported for now.
- File uploads aren't scanned. Pasted text and text attachments are.
