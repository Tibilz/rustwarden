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

- **Small.** The whole app is about 1.4 MB: roughly 520 kB WebAssembly and 140 kB Public Suffix List (loaded only when matching).
- **Idle means idle.** The background page is non-persistent. Keys live in `storage.session`
  (memory only), the encrypted vault in `storage.local`, and the WASM core is loaded only when
  cryptography is actually needed.
- **Little per-page work.** One small content script in the top frame: it reads one setting,
  optionally loads the passkey bridge, and registers a few passive listeners. Autofill is
  injected on demand, not kept in every page.
- **No framework** in the popup.

## Features

- Login to bitwarden.com, bitwarden.eu or a self-hosted server (e.g. Vaultwarden, also with a
  self-signed certificate);
  PBKDF2 and Argon2id; two-step login via authenticator app, email or YubiKey OTP;
  "remember this device"; new-device verification
- Vault: logins, cards, identities, secure notes, SSH keys (view only); folders, favorites,
  custom fields, password history, trash and restore; creating items inside organizations
- Autofill for logins (including TOTP) via popup, keyboard shortcut (⌘⇧L) or context menu;
  personal data (identities) and cards via popup or the context menus "Identität ausfüllen" /
  "Karte ausfüllen"
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

1. Copy `build/Build/Products/Release/RustWarden.app` to `/Applications` and open it once.
2. By default the app is only ad-hoc signed, so Safari requires *Settings → Developer → Allow
   unsigned extensions*, which it resets on every restart. To keep the extension enabled
   permanently, build with your Apple Development certificate (a free Apple ID team works;
   no provisioning profile is needed): `RW_TEAM=<your team ID> ./build.sh`. The team ID is the
   `OU` of your certificate (`security find-certificate -c "Apple Development" -p | openssl x509 -noout -subject`).
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
| `tests/crypto-interop.test.js` | Cross-checks the WASM core against an independent implementation (Node.js `crypto`): KDFs, EncStrings, attachment format, RFC 6238 vectors, tamper detection, malformed input. |
| `tools/gen-psl.js` | Regenerates `extension/psl.txt` from the Public Suffix List. |

## Testing

```sh
cd core && cargo test --release
node tests/crypto-interop.test.js # WASM core vs. Node.js crypto (needs extension/wasm from ./build.sh)
node tests/popup-render.test.js   # popup rendering and TOTP auto-copy, no browser needed
node tests/background-offline.test.js # background script without a server: context menus, identity fill
```

The end-to-end test needs a **throwaway** Vaultwarden with open registration. It creates two
accounts, so never point it at a real instance:

```sh
docker run -d --rm --name rw-test-vw -p 127.0.0.1:18080:80 \
  -e SIGNUPS_ALLOWED=true -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_MAX_BURST=1000 -e DOMAIN=http://localhost:18080 \
  vaultwarden/server:latest
./build.sh                      # or just the wasm-pack step
node tests/e2e.js extension
docker stop rw-test-vw          # --rm also removes the container's anonymous volume
```

It covers login (PBKDF2 and Argon2id), sync, item CRUD, URL matching, save prompts, the message
permission boundaries, passkey registration and assertion (signature verified), attachments,
Send, PIN unlock, export/import and account switching, plus attack scenarios: weak KDF parameters
from the server, non-HTTPS servers, public-suffix and look-alike domains, fills after navigation
or into http pages, forged inline-menu frames, swapped save prompts, oversized passkey options,
cross-rpId passkey replacement and passive commands keeping the vault unlocked. It does **not** exercise anything inside
Safari: the popup UI, autofill on real pages, the passkey page bridge, Touch ID and clipboard
clearing are untested.

## Security notes

Please read these before using the extension with a real vault. The code has been through an
internal review (crypto core, page/extension boundary, storage and locking); the findings and
the tests for them are in the test files. It has **not** had an independent audit.

What the client enforces:

- **Untrusted server.** Items are decrypted by schema: every encrypted field must be a valid,
  authenticated EncString (type 2), unknown fields are dropped and URI checksums are verified,
  so a server cannot inject plaintext such as a different URI. Unauthenticated type 0 data is
  only accepted for legacy keys without a MAC. KDF parameters from the server are bounds-checked
  (PBKDF2 100,000–2,000,000 iterations; Argon2id 2–10 iterations, 16–1024 MiB, parallelism
  1–16) instead of being used blindly. Server URLs must be HTTPS (plain HTTP only for localhost).
- **Domain matching** uses the full [Public Suffix List](https://publicsuffix.org), including its
  private section, so `evil.com.vn` does not match `bank.com.vn`. Passkey rpIds must not be a
  public suffix.
- **Filling** is bound to the origin the entry was chosen for: if the page navigates in between,
  nothing is filled. Credentials saved for `https` are not filled into an `http` page without
  explicit confirmation. Cross-origin frames are never filled.
- **In-page frames.** The inline menu only works with a one-time token handed out by the content
  script, so other pages or iframes cannot embed it. Passkey options from the page are
  sanitized and size-limited, and a passkey is never replaced by one for a different rpId.
- **Locking.** Locking always locks all accounts. Background activity (TOTP countdown, status
  checks, embedded menus) does not extend the auto-lock timer. Open popups discard their data
  when the vault locks.
- **PIN unlock** keeps the PIN-protected key in memory only by default, so the master password is
  needed after a browser restart. Persisting it is opt-in, requires at least 8 characters, and is
  offline-attackable by anyone who obtains your Safari profile files. After five wrong PINs
  (counted across restarts) the PIN is removed.

Known limitations:

- **Client identification.** Requests identify as the official browser client
  (`Bitwarden-Client-Name: browser`, with a fixed version string in `extension/background.js`),
  because servers may reject unknown clients. Whether bitwarden.com accepts this is untested.
- **Session key in memory.** While unlocked, the decrypted vault key is kept in the browser's
  session storage (RAM only) so the background page can unload. Access and refresh tokens are
  stored on disk, as in the official clients.
- **Organization keys** are protected only by RSA-OAEP, as in the Bitwarden protocol itself:
  a malicious server could substitute an organization key and plant items. This is inherent
  to the protocol.
- **Touch ID** is a UI gate: the unlock secret lives in the regular login keychain without a
  biometric access-control flag (that would require a provisioning profile).
- **Passkeys.** An unlocked vault counts as user verification; there is no extra prompt per
  sign-in. The confirmation dialog is an iframe inside the page, which the page could try to
  overlay. Interoperability with the official apps has not been verified.
- **"Starts with" and regex matching** behave like Bitwarden: `https://bank.com` as a "starts
  with" rule also matches `https://bank.com.evil.io`. Use base-domain or host matching unless
  you need these.
- **Clipboard.** Copied values are not marked as concealed for clipboard managers; clearing is
  off by default.
- **Autofill on page load** is off by default and limited to HTTPS; enabling it is a trade-off
  you should understand.
- **Exports are unencrypted.**

## Credits

- Passphrases use the [EFF large word list](https://www.eff.org/dice) by the Electronic
  Frontier Foundation, licensed under CC BY 3.0 US.
- Cryptography is provided by the RustCrypto crates.
- Domain matching uses the [Public Suffix List](https://publicsuffix.org) (`extension/psl.txt`),
  licensed under the Mozilla Public License 2.0.
- "Bitwarden" is a trademark of Bitwarden Inc.; "Vaultwarden" belongs to its respective
  project. They are mentioned only to describe compatibility.

## License

[MIT](LICENSE). The bundled EFF word list (`core/src/eff.txt`) remains under CC BY 3.0 US, the
Public Suffix List (`extension/psl.txt`) under MPL 2.0.
