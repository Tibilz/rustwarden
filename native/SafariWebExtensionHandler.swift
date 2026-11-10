//  RustWarden – native Seite der Safari-Erweiterung.
//  Aufgaben: Touch-ID-Freigabe eines im Schlüsselbund abgelegten Entsperr-Geheimnisses
//  und Leeren der Zwischenablage. Wird von build.sh ins Xcode-Projekt kopiert.

import AppKit
import CryptoKit
import LocalAuthentication
import SafariServices
import Security

private let keychainService = "dev.rustwarden.RustWarden.unlock"

class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {

    func beginRequest(with context: NSExtensionContext) {
        let item = context.inputItems.first as? NSExtensionItem
        let message = item?.userInfo?[SFExtensionMessageKey] as? [String: Any] ?? [:]
        handle(message) { reply in
            let response = NSExtensionItem()
            response.userInfo = [SFExtensionMessageKey: reply]
            context.completeRequest(returningItems: [response], completionHandler: nil)
        }
    }

    private func handle(_ m: [String: Any], _ done: @escaping ([String: Any]) -> Void) {
        let account = m["account"] as? String ?? ""
        switch m["cmd"] as? String {
        case "bioAvailable":
            var err: NSError?
            let ok = LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
            done(["ok": ok])

        case "bioStore":
            guard let secret = m["secret"] as? String, !account.isEmpty else {
                done(["error": "Ungültige Anfrage"])
                return
            }
            let status = keychainSet(account, secret)
            done(status == errSecSuccess ? ["ok": true] : ["error": "Schlüsselbund-Fehler \(status)"])

        case "bioGet":
            let ctx = LAContext()
            ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                               localizedReason: "den RustWarden-Tresor entsperren") { ok, error in
                guard ok else {
                    done(["error": error?.localizedDescription ?? "Touch ID abgebrochen"])
                    return
                }
                if let secret = self.keychainGet(account) {
                    done(["ok": true, "secret": secret])
                } else {
                    done(["error": "Kein Entsperr-Schlüssel im Schlüsselbund gefunden"])
                }
            }

        case "bioDelete":
            SecItemDelete(keychainQuery(account) as CFDictionary)
            done(["ok": true])

        case "clipClear":
            // Nur leeren, wenn noch der von RustWarden kopierte Wert in der Zwischenablage liegt.
            let expected = m["hash"] as? String ?? ""
            DispatchQueue.main.async {
                let pb = NSPasteboard.general
                var cleared = false
                if let current = pb.string(forType: .string) {
                    let digest = SHA256.hash(data: Data(current.utf8))
                    let hex = digest.map { String(format: "%02x", $0) }.joined()
                    if hex == expected {
                        pb.clearContents()
                        cleared = true
                    }
                }
                done(["ok": true, "cleared": cleared])
            }

        default:
            done(["error": "Unbekannter Befehl"])
        }
    }

    private func keychainQuery(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
        ]
    }

    private func keychainSet(_ account: String, _ secret: String) -> OSStatus {
        let query = keychainQuery(account)
        SecItemDelete(query as CFDictionary)
        var add = query
        add[kSecValueData as String] = Data(secret.utf8)
        return SecItemAdd(add as CFDictionary, nil)
    }

    private func keychainGet(_ account: String) -> String? {
        var query = keychainQuery(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess, let data = out as? Data else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }
}
