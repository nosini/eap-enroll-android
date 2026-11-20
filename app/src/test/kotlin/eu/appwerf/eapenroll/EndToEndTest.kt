package eu.appwerf.eapenroll

import java.io.File
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyPair
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import javax.net.ssl.SSLException
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * Runs [Enroller] against a real eap-enroll server with a fake OpenBao
 * (e2e/README.md). Skipped unless the harness is running: its control URL
 * comes from EAP_ENROLL_E2E_CONTROL or build/e2e/run/control.
 */
class EndToEndTest {
    private val control: String? = System.getenv("EAP_ENROLL_E2E_CONTROL")
        ?: File("../build/e2e/run/control").takeIf { it.exists() }?.readText()?.trim()

    private class MemoryKeys : DeviceKeys {
        val keys = HashMap<String, KeyPair>()
        private var next = 0

        override fun create(): String {
            val alias = "device-${next++}"
            keys[alias] = TestPki.keyPair("secp256r1")
            return alias
        }

        override fun keyPair(alias: String) = keys[alias] ?: throw IllegalStateException("no key $alias")

        override fun delete(alias: String) {
            keys.remove(alias)
        }
    }

    /** Stores JSON, so every step also goes through the state serialisation. */
    private class MemoryStore : StateStore {
        var json: String? = null

        override fun load() = json?.let { EnrollmentState.fromJson(JSONObject(it)) }

        override fun save(state: EnrollmentState?) {
            json = state?.toJson()?.toString()
        }
    }

    private class Install(val profile: WifiProfile, val identity: String, val key: PrivateKey, val chain: List<X509Certificate>)

    private class RecordingWifi : WifiInstaller {
        val installs = ArrayList<Install>()

        override fun install(profile: WifiProfile, identity: String, privateKey: PrivateKey, chain: List<X509Certificate>) {
            installs += Install(profile, identity, privateKey, chain)
        }
    }

    private val keys = MemoryKeys()
    private val store = MemoryStore()
    private val wifi = RecordingWifi()
    private var now = System.currentTimeMillis()
    private val enroller = Enroller(keys, wifi, store, log = { println(it) }, clock = { now })

    @Before
    fun needsHarness() {
        assumeTrue("e2e harness not running", control != null)
    }

    private fun call(method: String, path: String): String {
        val connection = URL(control + path).openConnection() as HttpURLConnection
        connection.requestMethod = method
        val status = connection.responseCode
        val body = (if (status < 400) connection.inputStream else connection.errorStream).use { it.readBytes() }
        check(status == 200) { "$path: HTTP $status ${String(body)}" }
        return String(body)
    }

    private fun code(user: String = "alice"): SetupUri = SetupUri.parse(call("POST", "/code?user=$user&label=E2E"))

    private fun revoked(mount: String): Set<BigInteger> {
        val json = JSONObject(call("GET", "/revoked"))
        val list = json.optJSONArray(mount) ?: return emptySet()
        return (0 until list.length()).map { BigInteger(list.getString(it).replace(":", ""), 16) }.toSet()
    }

    private fun deviceId(cert: X509Certificate): String =
        cert.subjectAlternativeNames.first { it[0] == 6 }[1].toString().removePrefix("urn:uuid:")

    @Test
    fun lifecycle() {
        assertEquals(Enroller.Outcome.OK, enroller.setup(code()))
        var state = store.load()!!
        assertEquals("alice", Certs.commonName(state.deviceChain[0]))
        assertTrue(deviceId(state.deviceChain[0]).isNotEmpty())

        // First Wi-Fi certificate, handed to Wi-Fi with the profile.
        assertEquals(1, wifi.installs.size)
        val first = wifi.installs[0]
        assertEquals("Example Net ", first.profile.ssid)
        assertEquals("radius.example.org", first.profile.serverDomain)
        assertEquals("alice", first.identity)
        assertEquals(384, (first.key as ECPrivateKey).params.curve.field.fieldSize)
        assertEquals(2, first.chain.size)
        assertEquals("E2E Wi-Fi CA", Certs.commonName(first.chain[1]))
        assertTrue(state.confirmPending)
        val firstSerial = state.wifiChain!![0].serialNumber

        // Nothing due yet.
        assertEquals(Enroller.Outcome.OK, enroller.maintain())
        assertEquals(1, wifi.installs.size)

        // A connection right after installing may predate it.
        assertFalse(enroller.connectionObserved(state.wifiInstalledAt + 1_000))
        assertTrue(enroller.connectionObserved(state.wifiInstalledAt + 60_000))
        assertEquals(Enroller.Outcome.OK, enroller.maintain())
        assertFalse(store.load()!!.confirmPending)
        assertFalse(firstSerial in revoked("pki-radius"))

        // A second certificate; confirming it revokes the first.
        now += 3_600_000
        assertEquals(Enroller.Outcome.OK, enroller.maintain(renewWifi = true))
        assertEquals(2, wifi.installs.size)
        state = store.load()!!
        assertNotEquals(firstSerial, state.wifiChain!![0].serialNumber)
        assertTrue(enroller.connectionObserved(now + 60_000))
        assertEquals(Enroller.Outcome.OK, enroller.maintain())
        assertTrue(firstSerial in revoked("pki-radius"))

        // 300 days later both are due: a new device key, then a Wi-Fi certificate with it.
        val oldAlias = state.deviceAlias
        val oldDevice = state.deviceChain[0].serialNumber
        now += 300L * 86_400_000
        assertEquals(Enroller.Outcome.OK, enroller.maintain())
        state = store.load()!!
        assertNotEquals(oldAlias, state.deviceAlias)
        assertNull(state.previousDeviceAlias)
        assertEquals(setOf(state.deviceAlias), keys.keys.keys)
        assertTrue(oldDevice in revoked("pki-enroll"))
        assertEquals(3, wifi.installs.size)
        assertNull(state.lastError)

        // Disabled by the administrator.
        call("POST", "/disable?device=${deviceId(state.deviceChain[0])}")
        assertEquals(Enroller.Outcome.STOPPED, enroller.maintain(renewWifi = true))
        state = store.load()!!
        assertTrue(state.problem != null)
        println("After disable: ${state.problem}, ${state.lastError}")
        assertEquals(Enroller.Outcome.STOPPED, enroller.maintain())
        assertEquals(3, wifi.installs.size)
    }

    @Test
    fun codeIsSingleUse() {
        val link = code()
        assertEquals(Enroller.Outcome.OK, enroller.setup(link))
        val other = Enroller(MemoryKeys(), RecordingWifi(), MemoryStore())
        val e = assertThrows(EstException::class.java) { other.setup(link) }
        assertEquals(401, e.status)
    }

    @Test
    fun wrongCaFingerprintIsRefused() {
        val text = call("POST", "/code?user=alice&label=E2E")
        val wrong = Hex.encode(MessageDigest.getInstance("SHA-256").digest(byteArrayOf(1)))
        val link = SetupUri.parse(text.replace(Regex("ca=[0-9a-f]{64}"), "ca=$wrong"))
        assertThrows(SSLException::class.java) { enroller.setup(link) }
        assertTrue(keys.keys.isEmpty())
        assertNull(store.load())
        // The code wasn't used up.
        assertEquals(Enroller.Outcome.OK, enroller.setup(SetupUri.parse(text)))
    }

    @Test
    fun disabledUserStops() {
        call("POST", "/group?user=carol&group=staff")
        assertEquals(Enroller.Outcome.OK, enroller.setup(code("carol")))
        call("POST", "/group?user=carol&group=disabled")
        assertEquals(Enroller.Outcome.STOPPED, enroller.maintain(renewWifi = true))
        assertEquals(Problem.DISABLED, store.load()!!.problem)
        assertEquals(1, wifi.installs.size)
    }
}
