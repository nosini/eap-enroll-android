package eu.appwerf.eapenroll

import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsServer
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.KeyPair
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Collections
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import org.json.JSONObject

/**
 * Device keys in memory. Keys made with a challenge get a stand-in
 * attestation chain (a certificate for the key, then a fake root); servers
 * that don't require attestation ignore it.
 */
class MemoryKeys : DeviceKeys {
    val keys = HashMap<String, KeyPair>()
    val challenges = ArrayList<ByteArray?>()

    /** Every key made, in order, including deleted ones. */
    val created = ArrayList<KeyPair>()
    private val attestations = HashMap<String, List<ByteArray>>()
    private val attestationRoot = TestPki.root("Fake Attestation Root")
    private var next = 0

    override fun create(challenge: ByteArray?): String {
        val alias = "device-${next++}"
        val keyPair = TestPki.keyPair("secp256r1")
        keys[alias] = keyPair
        created += keyPair
        challenges += challenge
        if (challenge != null) {
            attestations[alias] = listOf(
                TestPki.leaf(attestationRoot, "Android Keystore Key", keyPair).encoded,
                attestationRoot.cert.encoded,
            )
        }
        return alias
    }

    override fun keyPair(alias: String) = keys[alias] ?: throw IllegalStateException("no key $alias")

    override fun attestation(alias: String): List<ByteArray>? = attestations[alias]

    override fun delete(alias: String) {
        keys.remove(alias)
        attestations.remove(alias)
    }
}

/** Stores JSON, so every step also goes through the state serialisation. */
class MemoryStore : StateStore {
    var json: String? = null

    override fun load() = json?.let { EnrollmentState.fromJson(JSONObject(it)) }

    override fun save(state: EnrollmentState?) {
        json = state?.toJson()?.toString()
    }
}

class Install(val profile: WifiProfile, val identity: String, val key: PrivateKey, val chain: List<X509Certificate>)

class RecordingWifi : WifiInstaller {
    val installs = ArrayList<Install>()

    override fun install(profile: WifiProfile, identity: String, privateKey: PrivateKey, chain: List<X509Certificate>) {
        installs += Install(profile, identity, privateKey, chain)
    }
}

fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

/**
 * A local HTTPS server that answers every request with [answer], for
 * testing how the client handles the server's error answers. Its
 * certificate is for "localhost", issued by [ca]; [caFingerprint] goes where
 * the setup link's fingerprint would. It doesn't ask for client
 * certificates.
 */
class FakeEstServer : AutoCloseable {
    class Request(val method: String, val path: String, val headers: Map<String, String>)
    class Answer(val status: Int, val body: String = "", val headers: Map<String, String> = emptyMap())

    private val root = TestPki.root("Fake EST Root")
    private val ca = TestPki.intermediate(root, "Fake EST CA")
    val caFingerprint: String = Hex.encode(sha256(ca.cert.encoded))
    val requests: MutableList<Request> = Collections.synchronizedList(ArrayList())

    @Volatile
    var answer: (Request) -> Answer = { Answer(500, "no answer configured") }

    private val server: HttpsServer = HttpsServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0).apply {
        val keys = TestPki.keyPair()
        val leaf = TestPki.leaf(ca, "localhost", keys, serverAuth = true)
        val password = CharArray(0)
        val store = KeyStore.getInstance("PKCS12").apply {
            load(null)
            setKeyEntry("server", keys.private, password, arrayOf(leaf, ca.cert))
        }
        val keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            .apply { init(store, password) }.keyManagers
        httpsConfigurator = HttpsConfigurator(SSLContext.getInstance("TLS").apply { init(keyManagers, null, null) })
        createContext("/") { exchange ->
            val request = Request(
                exchange.requestMethod,
                exchange.requestURI.path.removePrefix("/.well-known/est/"),
                exchange.requestHeaders.mapKeys { it.key.lowercase() }.mapValues { it.value.first() },
            )
            exchange.requestBody.readBytes()
            requests += request
            val reply = answer(request)
            reply.headers.forEach { (name, value) -> exchange.responseHeaders.add(name, value) }
            exchange.responseHeaders.add("Content-Type", "text/plain; charset=utf-8")
            val body = reply.body.toByteArray()
            exchange.sendResponseHeaders(reply.status, if (body.isEmpty()) -1 else body.size.toLong())
            if (body.isNotEmpty()) exchange.responseBody.use { it.write(body) }
            exchange.close()
        }
        start()
    }

    val url: String = "https://localhost:${server.address.port}"

    override fun close() = server.stop(0)
}
