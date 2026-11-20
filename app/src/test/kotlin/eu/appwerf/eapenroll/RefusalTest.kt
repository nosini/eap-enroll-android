package eu.appwerf.eapenroll

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.util.Base64
import java.util.Date
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * How the enroller reacts to the server's error answers (the server's
 * docs/protocol.md), against a local server that answers with canned
 * errors. The device credential is due for renewal, so the first request of
 * every check is `device/simplereenroll`.
 */
class RefusalTest {
    private val server = FakeEstServer()
    private val keys = MemoryKeys()
    private val store = MemoryStore()
    private val wifi = RecordingWifi()
    private var now = System.currentTimeMillis()
    private val enroller = Enroller(keys, wifi, store, log = { println(it) }, clock = { now })
    private lateinit var credential: java.security.cert.X509Certificate
    private val day = 86_400_000L
    private val wifiCa = TestPki.root("Wi-Fi CA")

    /** Enrolled, with a device credential due for renewal and a Wi-Fi certificate that isn't. */
    @Before
    fun enrolled() {
        val deviceCa = TestPki.root("Device CA")
        val alias = keys.create()
        credential = TestPki.leaf(
            deviceCa, "alice", keys.keyPair(alias),
            notBefore = Date(now - 300 * day), notAfter = Date(now + 65 * day),
        )
        val wifiCert = TestPki.leaf(wifiCa, "alice", notBefore = Date(now - day), notAfter = Date(now + 59 * day))
        store.save(EnrollmentState(
            server.url, server.caFingerprint, alias, listOf(credential, deviceCa.cert),
            wifiChain = listOf(wifiCert, wifiCa.cert),
        ))
    }

    @After
    fun stop() = server.close()

    private fun answer(status: Int, vararg headers: Pair<String, String>) {
        server.answer = { FakeEstServer.Answer(status, "refused\n", headers.toMap()) }
    }

    @Test
    fun renewalSendsAttestationForTheCurrentCredential() {
        answer(403, "Enroll-Error" to "attestation_refused")
        assertEquals(Enroller.Outcome.LATER, enroller.maintain())

        val request = server.requests.single()
        assertEquals("device/simplereenroll", request.path)
        assertArrayEquals(sha256(credential.encoded), keys.challenges.last())
        val header = request.headers["key-attestation"]!!
        assertFalse(header.contains('\n'))
        val der = Base64.getDecoder().decode(header)
        // The chain for the CSR's key, leaf first.
        val chain = CertificateFactory.getInstance("X.509").generateCertificates(ByteArrayInputStream(der)).toList()
        assertEquals(2, chain.size)
        assertArrayEquals(keys.created.last().public.encoded, chain[0].publicKey.encoded)

        // The current credential stays, the refused key is gone, and nothing stops.
        val state = store.load()!!
        assertNull(state.problem)
        assertTrue(state.lastError!!.contains("attestation"))
        assertEquals(setOf(state.deviceAlias), keys.keys.keys)
    }

    @Test
    fun refusedAttestationDoesNotHoldUpWifiRenewal() {
        val old = TestPki.leaf(wifiCa, "alice", notBefore = Date(now - 45 * day), notAfter = Date(now + 15 * day))
        store.save(store.load()!!.copy(wifiChain = listOf(old, wifiCa.cert)))
        server.answer = {
            if (it.path == "device/simplereenroll") {
                FakeEstServer.Answer(403, "key attestation refused\n", mapOf("Enroll-Error" to "attestation_refused"))
            } else {
                FakeEstServer.Answer(503, "unavailable\n")
            }
        }
        // The Wi-Fi renewal is tried with the current credential; its failure decides what happens next.
        assertEquals(Enroller.Outcome.RETRY, enroller.maintain())
        assertEquals(listOf("device/simplereenroll", "wifi/profile"), server.requests.map { it.path })
        assertNull(store.load()!!.problem)
    }

    @Test
    fun disabledUserIsRetriedOnlyByTheUser() {
        answer(403, "Enroll-Error" to "user_disabled")
        assertEquals(Enroller.Outcome.STOPPED, enroller.maintain())
        assertEquals(Problem.USER_DISABLED, store.load()!!.problem)
        assertEquals(Enroller.Outcome.STOPPED, enroller.maintain())
        assertEquals(1, server.requests.size)

        // Still disabled, then a network-side failure: stays stopped for the background.
        answer(502)
        assertEquals(Enroller.Outcome.RETRY, enroller.maintain(byUser = true))
        assertEquals(2, server.requests.size)
        assertEquals(Problem.USER_DISABLED, store.load()!!.problem)
        assertEquals(Enroller.Outcome.STOPPED, enroller.maintain())
        assertEquals(2, server.requests.size)
    }

    @Test
    fun disabledDeviceNeedsSetup() {
        for (reason in listOf("device_disabled", "credential_reuse", null)) {
            store.save(store.load()!!.copy(problem = null))
            if (reason == null) answer(403) else answer(403, "Enroll-Error" to reason)
            assertEquals(reason, Enroller.Outcome.STOPPED, enroller.maintain())
            assertEquals(reason, Problem.DISABLED, store.load()!!.problem)
            val before = server.requests.size
            assertEquals(Enroller.Outcome.STOPPED, enroller.maintain(byUser = true))
            assertEquals(before, server.requests.size)
        }
    }

    @Test
    fun unknownCredentialNeedsSetup() {
        answer(401, "Enroll-Error" to "unknown_cert")
        assertEquals(Enroller.Outcome.STOPPED, enroller.maintain())
        assertEquals(Problem.NEEDS_SETUP, store.load()!!.problem)
    }

    @Test
    fun malformedReasonIsIgnored() {
        answer(403, "Enroll-Error" to "User Disabled!")
        assertEquals(Enroller.Outcome.STOPPED, enroller.maintain())
        assertEquals(Problem.DISABLED, store.load()!!.problem)
    }

    @Test
    fun setupAttestsTheCode() {
        store.save(null)
        answer(400, "Enroll-Error" to "bad_attestation")
        val code = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        val link = SetupUri.parse("eapenroll://setup?v=1&url=${server.url}&ca=${server.caFingerprint}&code=$code")
        val e = runCatching { enroller.setup(link) }.exceptionOrNull() as EstException
        assertEquals("bad_attestation", e.reason)
        val request = server.requests.single()
        assertEquals("Bearer $code", request.headers["authorization"])
        assertNotNull(request.headers["key-attestation"])
        assertArrayEquals(sha256(code.toByteArray()), keys.challenges.last())
        // The key made for the refused setup is deleted; the one from @Before stays.
        assertEquals(1, keys.keys.size)
        assertNull(store.load())
    }
}

class AttestationHeaderTest {
    @Test
    fun concatenatedDerInOneLine() {
        val a = ByteArray(100) { 1 }
        val b = ByteArray(200) { 2 }
        val header = EstClient.attestationHeader(listOf(a, b))
        assertFalse(header.contains('\n') || header.contains('\r'))
        assertArrayEquals(a + b, Base64.getDecoder().decode(header))
    }

    @Test
    fun errorMessagesNameTheReason() {
        val e = EstException(403, "key attestation refused", reason = "attestation_refused")
        assertEquals("HTTP 403 (attestation_refused): key attestation refused", e.message)
        assertTrue(Errors.describe(e).contains("refused this phone's key attestation"))
        assertTrue(Errors.describe(EstException(429, "too many requests", 90)).contains("wait 2 minute"))
        assertEquals("EstException: HTTP 500: internal error", Errors.describe(EstException(500, "internal error")))
    }
}
