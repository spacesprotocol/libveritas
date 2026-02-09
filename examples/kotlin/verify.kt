/// Kotlin example consuming libveritas via UniFFI bindings.
///
/// Build & run (from repo root, requires JNA on classpath):
///   kotlinc bindings/uniffi/bindings/kotlin/uniffi/libveritas_uniffi/libveritas_uniffi.kt \
///     examples/kotlin/verify.kt \
///     -cp jna.jar -include-runtime -d examples/kotlin/verify.jar
///
///   java -Djna.library.path=target/debug -jar examples/kotlin/verify.jar

package examples

import uniffi.libveritas_uniffi.*
import java.io.File

fun main() {
    // Load fixtures
    val anchorsJson = File("examples/fixture/anchors.json").readText()
    val msg = File("examples/fixture/message.bin").readBytes()

    // Create verifier
    val anchors = VeritasAnchors.fromJson(anchorsJson)
    val veritas = Veritas(anchors, devMode = true)
    println("anchors: ${veritas.oldestAnchor()} .. ${veritas.newestAnchor()}")

    // Build query context (empty = verify all handles)
    val ctx = VeritasQueryContext()

    // Verify message
    val result = veritas.verifyMessage(ctx, msg)

    // Zones
    val zones = result.zones()
    println("\n${zones.size} zones verified:")
    for (z in zones) {
        println("  ${z.handle()} -> ${z.sovereignty()} (anchor ${z.anchor()})")

        when (val c = z.commitment()) {
            is VeritasCommitmentState.Exists ->
                println("    commitment: exists (block ${c.blockHeight}, root ${c.stateRoot.size} bytes)")
            is VeritasCommitmentState.Empty ->
                println("    commitment: empty")
            is VeritasCommitmentState.Unknown ->
                println("    commitment: unknown")
        }

        when (val d = z.delegate()) {
            is VeritasDelegateState.Exists ->
                println("    delegate: exists (spk ${d.scriptPubkey.size} bytes)")
            is VeritasDelegateState.Empty ->
                println("    delegate: empty")
            is VeritasDelegateState.Unknown ->
                println("    delegate: unknown")
        }
    }

    // Zone comparison
    if (zones.size >= 2) {
        try {
            val better = zones[0].isBetterThan(zones[1])
            println("\n${zones[0].handle()} better than ${zones[1].handle()}? $better")
        } catch (e: Exception) {
            println("\nisBetterThan: ${e.message} (expected — different handles)")
        }
    }

    // Zone bytes for storage
    val sovereignBytes = zones[0].toBytes()
    println("\n${zones[0].handle()} zone bytes: ${sovereignBytes.size} bytes")

    // Certificates
    val certs = result.certificates()
    println("\n${certs.size} certificates:")
    for (c in certs) {
        println("  ${c.subject} [${c.certType}] (${c.bytes.size} bytes)")
    }

    // Single certificate lookup
    val alice = result.certificate("alice@sovereign")
    if (alice != null) {
        println("\nalice@sovereign certificate: ${alice.subject} [${alice.certType}]")
    }

    println("\ndone.")
}
