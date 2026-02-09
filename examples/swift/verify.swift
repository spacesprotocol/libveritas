/// Swift example consuming libveritas via UniFFI bindings.
///
/// Build & run (from repo root):
///   swiftc -import-objc-header bindings/uniffi/bindings/swift/libveritas_uniffiFFI.h \
///     bindings/uniffi/bindings/swift/libveritas_uniffi.swift \
///     examples/swift/verify.swift \
///     -L target/debug -llibveritas_uniffi \
///     -o examples/swift/verify
///
///   DYLD_LIBRARY_PATH=target/debug ./examples/swift/verify

import Foundation

@main
struct Verify {
    static func main() throws {
        // Load fixtures
        let anchorsJson = try String(contentsOfFile: "examples/fixture/anchors.json", encoding: .utf8)
        let msg = try Data(contentsOf: URL(fileURLWithPath: "examples/fixture/message.bin"))

        // Create verifier
        let anchors = try VeritasAnchors.fromJson(json: anchorsJson)
        let veritas = try Veritas(anchors: anchors, devMode: true)
        print("anchors: \(veritas.oldestAnchor()) .. \(veritas.newestAnchor())")

        // Build query context (empty = verify all handles)
        let ctx = VeritasQueryContext()

        // Verify message
        let result = try veritas.verifyMessage(ctx: ctx, msg: msg)

        // Zones
        let zones = result.zones()
        print("\n\(zones.count) zones verified:")
        for z in zones {
            print("  \(z.handle()) -> \(z.sovereignty()) (anchor \(z.anchor()))")

            switch z.commitment() {
            case .exists(let stateRoot, _, _, let blockHeight, _):
                print("    commitment: exists (block \(blockHeight), root \(stateRoot.count) bytes)")
            case .empty:
                print("    commitment: empty")
            case .unknown:
                print("    commitment: unknown")
            }

            switch z.delegate() {
            case .exists(let spk, _):
                print("    delegate: exists (spk \(spk.count) bytes)")
            case .empty:
                print("    delegate: empty")
            case .unknown:
                print("    delegate: unknown")
            }
        }

        // Zone comparison
        if zones.count >= 2 {
            do {
                let better = try zones[0].isBetterThan(other: zones[1])
                print("\n\(zones[0].handle()) better than \(zones[1].handle())? \(better)")
            } catch {
                print("\nisBetterThan: \(error) (expected — different handles)")
            }
        }

        // Zone bytes for storage
        let sovereignBytes = zones[0].toBytes()
        print("\n\(zones[0].handle()) zone bytes: \(sovereignBytes.count) bytes")

        // Certificates
        let certs = result.certificates()
        print("\n\(certs.count) certificates:")
        for c in certs {
            print("  \(c.subject) [\(c.certType)] (\(c.bytes.count) bytes)")
        }

        // Single certificate lookup
        if let alice = try result.certificate(handle: "alice@sovereign") {
            print("\nalice@sovereign certificate: \(alice.subject) [\(alice.certType)]")
        }

        print("\ndone.")
    }
}
