<div align="center">

# AI Prompt Redaction (APR)

  <img src="icons/icon.svg" alt="AI Prompt Redaction icon" width="96" height="96">

</div>

Scans messages on claude.ai and redacts secrets and sensitive data before they are sent.

> [!IMPORTANT]
>
> This project was built with AI assistance (Claude). The code,
> tests and documentation were largely written by AI, and every
> change is reviewed by me before it's merged.

## Features

- **Redacts before sending** - API keys, passwords, card numbers, ID numbers and similar values are replaced with placeholders such as `[REDACTED_EMAIL_1]` before your message leaves the browser. It works however the message is sent: Enter, the send button, retry or edit.
- **Consistent placeholders** - the same value always gets the same placeholder within a page session, so the AI can still follow references to it.
- **Shows what it changed** - values that will be redacted are highlighted in the message box as you type. After sending, a toast confirms what was removed, and the original values stay marked in the chat with a tooltip showing what the AI received instead.
- **Configurable** - turn individual detectors on or off, and add your own custom terms (client names, codenames, internal project names).
- **Try it** - paste text into the popup to preview what would be redacted.
- **Local-only** - all scanning happens in your browser. The extension makes no network requests of its own.

## What it detects

Detectors marked _(off)_ are off by default because they can match ordinary codes. Turn them on in the popup.

**Personal information**

- Contact details: email addresses, phone numbers with country code, Indian mobile numbers, UPI IDs
- Government IDs: Aadhaar (checksum-validated), PAN, GSTIN, US Social Security numbers, Voter IDs _(off)_, Indian passport numbers _(off)_
- Financial: card numbers (checksum-validated), IBANs, labelled bank account numbers

**Code and technical**

- Keys and tokens: private keys, AWS, Anthropic, OpenAI, GitHub, Stripe, Slack, Google/Firebase, Azure, npm, PyPI, GitLab, Hugging Face, SendGrid, Twilio, Shopify, DigitalOcean and Telegram tokens, webhook URLs, JSON Web Tokens
- Config, headers and commands: passwords in URLs, secrets in URL parameters, secret values in configs and `.env` files, `Authorization` and `Cookie` headers, passwords in `curl -u`, random-looking strings _(off)_
- Network and infrastructure: IPv4 and IPv6 addresses, MAC addresses, internal hostnames, usernames in file paths, AWS account IDs in ARNs

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

Found a miss or a false positive? [Open a detection issue](https://github.com/Aadityajoshi151/AI-Prompt-Redaction/issues/new/choose)
