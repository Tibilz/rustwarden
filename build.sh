#!/bin/zsh
# Baut den WASM-Kern und die Safari-App (ad-hoc signiert, für lokale Nutzung).
#   ./build.sh           normaler Build
#   ./build.sh --regen   Xcode-Projekt neu erzeugen (nötig, wenn Dateien in extension/ hinzukommen;
#                        setzt eigene Signatur-Einstellungen im Projekt zurück)
set -euo pipefail
cd "$(dirname "$0")"
PROJ=safari/RustWarden

echo "==> Rust-Kern testen"
(cd core && cargo test --release --quiet)

echo "==> WASM bauen"
# Absolute Pfade (Benutzername!) nicht in die Binärdatei einkompilieren.
export RUSTFLAGS="--remap-path-prefix=$HOME=~ --remap-path-prefix=$PWD=."
(cd core && wasm-pack build --release --target no-modules --no-typescript --out-dir ../extension/wasm)
rm -f extension/wasm/package.json extension/wasm/.gitignore extension/wasm/README.md

if [[ "${1:-}" == "--regen" || ! -d $PROJ/RustWarden.xcodeproj ]]; then
  echo "==> Xcode-Projekt erzeugen"
  xcrun safari-web-extension-converter extension \
    --project-location safari --app-name RustWarden \
    --bundle-identifier dev.rustwarden.RustWarden \
    --macos-only --swift --no-open --no-prompt --force
fi
cp native/SafariWebExtensionHandler.swift "$PROJ/RustWarden Extension/SafariWebExtensionHandler.swift"

echo "==> Safari-App bauen"
xcodebuild -project $PROJ/RustWarden.xcodeproj -scheme RustWarden \
  -configuration Release -derivedDataPath build \
  CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM= \
  build -quiet

echo "==> Fertig: build/Build/Products/Release/RustWarden.app"
