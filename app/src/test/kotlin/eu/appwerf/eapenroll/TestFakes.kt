package eu.appwerf.eapenroll

import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsExchange
import com.sun.net.httpserver.HttpsParameters
import com.sun.net.httpserver.HttpsServer
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.Collections
import java.util.Date
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * Device keys in memory. Keys made with a challenge get a stand-in
 * attestation chain (a certificate for the key, then a fake root); servers
 * that don't require attestation ignore it. Without [attest], keys have no
 * attestation, like the Keystore's fallback when attesting fails.
 */
class MemoryKeys : DeviceKeys {
    val keys = HashMap<String, KeyPair>()
    val challenges = ArrayList<ByteArray?>()

    /** Every key made, in order, including deleted ones. */
    val created = ArrayList<KeyPair>()
    private val attestations = HashMap<String, List<ByteArray>>()
    private val attestationRoot = TestPki.root("Fake Attestation Root")
    private var next = 0

    /** Thrown by [create] instead of making a key, like a Keystore that fails. */
    var createFailure: Exception? = null

    var attest = true

    override fun create(challenge: ByteArray?): String {
        createFailure?.let { throw it }
        val alias = "device-${next++}"
        val keyPair = TestPki.keyPair("secp256r1")
        keys[alias] = keyPair
        created += keyPair
        challenges += challenge
        if (challenge != null && attest) {
            attestations[alias] = listOf(
                TestPki.leaf(attestationRoot, "Android Keystore Key", keyPair).encoded,
                attestationRoot.cert.encoded,
            )
        }
        return alias
    }

    override fun keyPair(alias: String) = keys[alias] ?: throw MissingDeviceKeyException(alias)

    override fun attestation(alias: String): List<ByteArray>? = attestations[alias]

    override fun delete(alias: String) {
        keys.remove(alias)
        attestations.remove(alias)
    }

    override fun deleteOthers(keep: Set<String>) {
        (keys.keys - keep).forEach(::delete)
    }
}

/** Stores JSON, so every step also goes through the state serialisation. */
class MemoryStore : StateStore {
    var json: String? = null

    override fun load() = json?.let(EnrollmentState::parse)

    override fun save(state: EnrollmentState?) {
        json = state?.toJson()?.toString()
    }
}

class Install(val profile: WifiProfile, val wpa3: Boolean, val identity: String, val key: PrivateKey, val chain: List<X509Certificate>)

class RecordingWifi : WifiInstaller {
    val installs = ArrayList<Install>()

    /** Thrown by [install], like a suggestion Wi-Fi refuses. */
    var installFailure: Exception? = null

    /** Thrown by [checkAllowed], like Wi-Fi control turned off. */
    var notAllowed: WifiInstallException? = null

    /** What [isInstalled] answers; set to false to simulate Android removing the suggestion. */
    var installed = true

    override fun install(profile: WifiProfile, wpa3: Boolean, identity: String, privateKey: PrivateKey, chain: List<X509Certificate>) {
        installFailure?.let { throw it }
        installs += Install(profile, wpa3, identity, privateKey, chain)
        installed = true
    }

    override fun checkAllowed() {
        notAllowed?.let { throw it }
    }

    override fun isInstalled(profile: WifiProfile): Boolean = installed
}

fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

/**
 * A local HTTPS server that answers every request with [answer], for
 * testing how the client handles the server's error answers. Its
 * certificate is for [hostName], issued by [ca]; [caFingerprint] goes where
 * the setup link's fingerprint would. It speaks TLS 1.3 only, like the real
 * server. Like the real server, it asks for a client certificate without
 * requiring one, and a client certificate it gets must be valid and issued
 * by [deviceCa], or the handshake fails. It records every one it gets.
 */
class FakeEstServer(hostName: String = "localhost") : AutoCloseable {
    class Request(
        val method: String,
        val path: String,
        val headers: Map<String, String>,
        val clientCertificate: X509Certificate?,
        val body: ByteArray,
    )
    class Answer(val status: Int, val body: String = "", val headers: Map<String, String> = emptyMap())

    companion object {
        /** A certificate from [issuer] for the key in the request's CSR, as the server sends it. */
        fun issue(
            request: Request,
            issuer: TestPki.Issuer,
            name: String,
            notBefore: Date = Date(System.currentTimeMillis() - 3_600_000),
            notAfter: Date = Date(System.currentTimeMillis() + 86_400_000),
            /** Certificates after the issuer's, e.g. its CA. */
            moreChain: List<X509Certificate> = emptyList(),
        ): Answer {
            val leaf = TestPki.leaf(issuer, name, KeyPair(csrKey(request), null), notBefore, notAfter)
            return certificates(listOf(leaf, issuer.cert) + moreChain)
        }

        /** The public key in the request's CSR. */
        fun csrKey(request: Request): PublicKey {
            val csr = Base64.getMimeDecoder().decode(request.body)
            val info = Der.parse(csr).children()[0]
            return KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(info.children()[2].encoded()))
        }

        /** [chain] as a certs-only answer. */
        fun certificates(chain: List<X509Certificate>) = Answer(
            200,
            Base64.getEncoder().encodeToString(TestPki.certsOnly(chain)),
            mapOf("Content-Type" to "application/pkcs7-mime; smime-type=certs-only"),
        )

        /** The answer to `wifi/profile`. */
        fun profile(profile: WifiProfile) =
            Answer(200, Profiles.toJson(profile).toString(), mapOf("Content-Type" to "application/json"))
    }

    private val root = TestPki.root("Fake EST Root")
    private val ca = TestPki.intermediate(root, "Fake EST CA")
    val caFingerprint: String = Hex.encode(sha256(ca.cert.encoded))

    /** The CA whose client certificates the server accepts: device credentials come from it. */
    val deviceCa: TestPki.Issuer = TestPki.root("Fake Device CA")
    val requests: MutableList<Request> = Collections.synchronizedList(ArrayList())

    /** Client certificates received in handshakes, whether or not a request followed. */
    val handshakeClientCertificates: MutableList<X509Certificate> = Collections.synchronizedList(ArrayList())

    @Volatile
    var answer: (Request) -> Answer = { Answer(500, "no answer configured") }

    private val server: HttpsServer = HttpsServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0).apply {
        val keys = TestPki.keyPair()
        val leaf = TestPki.leaf(ca, hostName, keys, serverAuth = true)
        val password = CharArray(0)
        val store = KeyStore.getInstance("PKCS12").apply {
            load(null)
            setKeyEntry("server", keys.private, password, arrayOf(leaf, ca.cert))
        }
        val keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            .apply { init(store, password) }.keyManagers
        val context = SSLContext.getInstance("TLS").apply {
            init(keyManagers, arrayOf(DeviceClients(deviceCa, handshakeClientCertificates)), null)
        }
        httpsConfigurator = object : HttpsConfigurator(context) {
            override fun configure(params: HttpsParameters) {
                params.setSSLParameters(context.defaultSSLParameters.apply {
                    wantClientAuth = true
                    protocols = arrayOf("TLSv1.3")
                })
            }
        }
        createContext("/") { exchange ->
            val request = Request(
                exchange.requestMethod,
                exchange.requestURI.path.removePrefix("/.well-known/est/"),
                exchange.requestHeaders.mapKeys { it.key.lowercase() }.mapValues { it.value.first() },
                runCatching { (exchange as HttpsExchange).sslSession.peerCertificates[0] as X509Certificate }.getOrNull(),
                exchange.requestBody.readBytes(),
            )
            requests += request
            val reply = answer(request)
            reply.headers.forEach { (name, value) -> exchange.responseHeaders.add(name, value) }
            if (!exchange.responseHeaders.containsKey("Content-Type")) {
                exchange.responseHeaders.add("Content-Type", "text/plain; charset=utf-8")
            }
            val body = reply.body.toByteArray()
            exchange.sendResponseHeaders(reply.status, if (body.isEmpty()) -1 else body.size.toLong())
            if (body.isNotEmpty()) exchange.responseBody.use { it.write(body) }
            exchange.close()
        }
        start()
    }

    val url: String = "https://localhost:${server.address.port}"

    /** Records client certificates, then checks them against [ca] (validity, chain, client auth). */
    private class DeviceClients(ca: TestPki.Issuer, private val seen: MutableList<X509Certificate>) : X509TrustManager {
        private val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
            init(KeyStore.getInstance("PKCS12").apply {
                load(null)
                setCertificateEntry("device-ca", ca.cert)
            })
        }.trustManagers.single() as X509TrustManager

        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            chain?.firstOrNull()?.let { seen += it }
            trust.checkClientTrusted(chain, authType)
        }

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) =
            throw CertificateException("not a client")

        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    override fun close() = server.stop(0)
}
