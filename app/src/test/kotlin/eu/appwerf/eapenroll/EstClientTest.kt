package eu.appwerf.eapenroll

import java.io.IOException
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** What the client accepts from the server, against a local server. */
class EstClientTest {
    private val server = FakeEstServer()
    private val keys = MemoryKeys()
    private val alias = keys.create()
    private val credential = TestPki.leaf(server.deviceCa, "alice", keys.keyPair(alias))
    private val code = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    @After
    fun stop() = server.close()

    private fun client() = EstClient(server.url, server.caFingerprint, ClientCredential(keys.keyPair(alias).private, listOf(credential)))

    private fun enrollDevice(client: EstClient) =
        client.enrollDevice(code, Csr.create(keys.keyPair(alias), "eap-enroll"), keys.attestation(alias))

    @Test
    fun redirectsAreNotFollowed() {
        server.answer = {
            FakeEstServer.Answer(302, "", mapOf("Location" to "${server.url}/.well-known/est/elsewhere"))
        }
        for ((label, request) in listOf<Pair<String, (EstClient) -> Unit>>(
            "wifi/profile" to { it.wifiProfile() },
            // The one-time code mustn't go anywhere else.
            "device/simpleenroll" to { enrollDevice(it) },
        )) {
            server.requests.clear()
            val e = assertThrows(label, EstException::class.java) { request(client()) }
            assertEquals(label, 302, e.status)
            assertEquals(label, listOf(label), server.requests.map { it.path })
        }
    }

    @Test
    fun largeAnswersAreRefused() {
        val issuer = TestPki.root("Device CA")
        server.answer = {
            val certificates = FakeEstServer.issue(it, issuer, "alice")
            // Base64 with line breaks is allowed; this is just too much of it.
            FakeEstServer.Answer(200, certificates.body + "\r\n".repeat(140 * 1024), certificates.headers)
        }
        val e = assertThrows(IOException::class.java) { enrollDevice(client()) }
        assertTrue(e.message, e.message!!.contains("larger than 256 KiB"))

        server.answer = {
            FakeEstServer.Answer(200, "{\"x\":\"${"x".repeat(300 * 1024)}\"}", mapOf("Content-Type" to "application/json"))
        }
        assertThrows(IOException::class.java) { client().wifiProfile() }
    }

    @Test
    fun certificatesOnlyAsPkcs7() {
        val issuer = TestPki.root("Wi-Fi CA")
        for (type in listOf("text/plain", "application/pkcs7", "application/json")) {
            server.answer = {
                val certificates = FakeEstServer.certificates(listOf(issuer.cert))
                FakeEstServer.Answer(200, certificates.body, mapOf("Content-Type" to type))
            }
            val e = assertThrows(type, IOException::class.java) { client().wifiCaCertificates() }
            assertTrue(type, e.message!!.contains("Unexpected response type"))
        }
        server.answer = { FakeEstServer.certificates(listOf(issuer.cert)) }
        assertEquals(listOf(issuer.cert), client().wifiCaCertificates())
    }
}
