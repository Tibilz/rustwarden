#!/bin/zsh
# Baut den WASM-Kern und die Safari-App.
#   ./build.sh           normaler Build (ad-hoc signiert; Safari braucht „Nicht signierte Erweiterungen erlauben“)
#   RW_TEAM=ABCDE12345 ./build.sh
#                        mit deinem Apple-Development-Zertifikat signieren (auch kostenloses Apple-ID-Team);
#                        die Erweiterung bleibt dann über Safari-Neustarts hinweg aktiv
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
if [[ -n "${RW_TEAM:-}" ]]; then
  SIGN=(CODE_SIGN_STYLE=Automatic DEVELOPMENT_TEAM="$RW_TEAM" -allowProvisioningUpdates)
else
  SIGN=(CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM=)
fi
xcodebuild -project $PROJ/RustWarden.xcodeproj -scheme RustWarden \
  -configuration Release -derivedDataPath build \
  "${SIGN[@]}" build -quiet

echo "==> Fertig: build/Build/Products/Release/RustWarden.app"
