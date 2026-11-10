# RustWarden

A lightweight, Bitwarden-compatible password manager extension for Safari on macOS.
All cryptography runs in a small Rust core compiled to WebAssembly; the UI is plain DOM
without a framework, and the background page unloads when idle.

> **Status: experimental and unaudited.** This is an independent hobby project. It is not
> affiliated with, endorsed by, or supported by Bitwarden Inc. or the Vaultwarden project.
> The server protocol was implemented from public knowledge of the API and verified against
> a local Vaultwarden instance, but the extension has not had real-world testing inside
> Safari and has not been security-reviewed. Do not rely on it as your only way into your vault.

## Why

The goal is a client that costs almost nothing while you are not using it:

- **Small.** The whole app is about 1.2 MB, roughly 490 kB of which is WebAssembly.
- **Idle means idle.** The background page is non-persistent. Keys live in `storage.session`
  (memory only), the encrypted vault in `storage.local`, and the WASM core is loaded only when
  cryptography is actually needed.
- **Little per-page work.** One small content script in the top frame: it reads one setting,
  optionally loads the passkey bridge, and registers a few passive listeners. Autofill is
  injected on demand, not kept in every page.
- **No framework** in the popup.

## Features

- Login to bitwarden.com, bitwarden.eu or a self-hosted server (e.g. Vaultwarden);
  PBKDF2 and Argon2id; two-step login via authenticator app, email or YubiKey OTP;
  "remember this device"; new-device verification
- Vault: logins, cards, identities, secure notes, SSH keys (view only); folders, favorites,
  custom fields, password history, trash and restore; creating items inside organizations
- Autofill for logins (including TOTP), cards and identities via popup, keyboard shortcut
  (⌘⇧L) or context menu
- Offer to save new or changed logins
- Passkeys (WebAuthn, ES256): create, store in the vault, sign in
- Attachments: upload, download, delete
- Send: text and file
- TOTP codes (including `otpauth://` URIs and Steam)
- Generator: passwords, passphrases (EFF word list), usernames
- Unlock with master password, PIN or Touch ID; auto-lock timer; master password re-prompt
- Multiple accounts
- Export / import (unencrypted Bitwarden JSON)
- Optional, off by default because they cost performance: inline menu below login fields,
  match counter on the toolbar icon, autofill on page load

### Not supported

- SSO, Duo, WebAuthn as a second factor, login with device
- Live sync via push notifications (sync happens on unlock, when the popup opens with stale
  data, and via the sync button)
- Offline changes: saving requires the server to be reachable
- Collection management, encrypted exports, password-protected Sends, email forwarding services
- Accounts using the newer account key format (encryption type 7)
- Passkey limitations: one passkey per item, ES256 only, conditional mediation (autofill
  suggestions) is left to Safari

## Requirements

- macOS with Xcode (for `safari-web-extension-converter` and `xcodebuild`), Safari 16.4+
- Rust with the `wasm32-unknown-unknown` target, and [`wasm-pack`](https://rustwasm.github.io/wasm-pack/)
- Node.js (only for the end-to-end test)

## Build

```sh
./build.sh
```

This runs the Rust tests, builds the WASM core into `extension/wasm/`, generates the Xcode
project under `safari/` (if missing) and builds an ad-hoc signed app at
`build/Build/Products/Release/RustWarden.app`.

Use `./build.sh --regen` after adding files to `extension/`; this regenerates the Xcode project
and resets any signing settings you changed in it.

## Install

1. Open `build/Build/Products/Release/RustWarden.app` once.
2. The app is only ad-hoc signed. In Safari, enable *Settings → Developer → Allow unsigned
   extensions* (Safari resets this on every restart). To avoid that, sign the app with your
   own team in Xcode.
3. Enable RustWarden under *Settings → Extensions* and allow it to access websites — at least
   your server's address, otherwise login fails.

**Self-hosted servers with a self-signed certificate:** the certificate must be trusted in the
macOS keychain ("Always Trust"). If Safari opens your server's web vault without a warning,
the extension can reach it too.

## Project layout

| Path | Purpose |
| --- | --- |
| `core/` | Rust crate: KDF, EncString encryption (AES-256-CBC + HMAC-SHA256), RSA-OAEP, vault encryption/decryption, TOTP, generators. Stateless, JSON in/out. |
| `extension/` | The web extension: background page, popup, content script, inline menu and passkey dialog. |
| `native/` | Swift handler for Touch ID (keychain-backed unlock secret) and clipboard clearing. Copied into the Xcode project by `build.sh`. |
| `tests/e2e.js` | End-to-end test that loads the unmodified background script into a Node VM and runs it against a real server. |

## Testing

```sh
cd core && cargo test --release
```

The end-to-end test needs a **throwaway** Vaultwarden with open registration. It creates two
accounts, so never point it at a real instance:

```sh
docker run -d --name rw-test-vw -p 127.0.0.1:18080:80 \
  -e SIGNUPS_ALLOWED=true -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_MAX_BURST=1000 -e DOMAIN=http://localhost:18080 \
  vaultwarden/server:latest
./build.sh                      # or just the wasm-pack step
node tests/e2e.js extension
docker rm -f rw-test-vw
```

It covers login (PBKDF2 and Argon2id), sync, item CRUD, URL matching, save prompts, the message
permission boundaries, passkey registration and assertion (signature verified), attachments,
Send, PIN unlock, export/import and account switching. It does **not** exercise anything inside
Safari: the popup UI, autofill on real pages, the passkey page bridge, Touch ID and clipboard
clearing are untested.

## Security notes

Please read these before using the extension with a real vault.

- **Client identification.** Requests identify as the official browser client
  (`Bitwarden-Client-Name: browser`, with a fixed version string in `extension/background.js`),
  because servers may reject unknown clients. Whether bitwarden.com accepts this is untested.
- **Domain matching** uses a short built-in suffix list instead of the full Public Suffix List.
  On hosting domains that are missing from that list, entries of sibling subdomains can be
  suggested, and the keyboard shortcut fills the first match.
- **Session key in memory.** While unlocked, the decrypted vault key is kept in the browser's
  session storage (RAM only) so the background page can unload.
- **PIN unlock** stores the vault key encrypted with a PIN-derived key on disk. Anyone who
  obtains that file can brute-force a short PIN offline. The PIN is removed after five failed
  attempts in the extension.
- **Touch ID** keeps its unlock secret in the regular login keychain, not in the Secure Enclave.
- **Passkeys.** An unlocked vault counts as user verification; there is no extra prompt per
  sign-in. The stored format follows the one used by Bitwarden clients, but interoperability
  with the official apps has not been verified.
- **In-page dialogs** (passkey dialog, inline menu) are extension iframes inside the page. The
  page cannot read them, but it controls the surrounding DOM, so clickjacking-style tricks are
  conceivable. They can only ever act on entries matching the current site.
- **Autofill on page load** is off by default and limited to HTTPS; enabling it is a trade-off
  you should understand.
- **Exports are unencrypted.**

## Credits

- Passphrases use the [EFF large word list](https://www.eff.org/dice) by the Electronic
  Frontier Foundation, licensed under CC BY 3.0 US.
- Cryptography is provided by the RustCrypto crates.
- "Bitwarden" is a trademark of Bitwarden Inc.; "Vaultwarden" belongs to its respective
  project. They are mentioned only to describe compatibility.

## License

[MIT](LICENSE). The bundled EFF word list (`core/src/eff.txt`) remains under CC BY 3.0 US.
