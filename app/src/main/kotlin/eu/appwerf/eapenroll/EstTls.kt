package eu.appwerf.eapenroll

import android.annotation.SuppressLint
import java.net.InetAddress
import java.net.Socket
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.CertificateException
import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509ExtendedTrustManager
import javax.net.ssl.X509TrustManager

/** A client certificate and its key, for mutual TLS with the enrollment server. */
class ClientCredential(val privateKey: PrivateKey, val chain: List<X509Certificate>) {
    init {
        require(chain.isNotEmpty()) { "Empty certificate chain" }
    }
}

/** TLS setup for the enrollment server. */
object EstTls {
    /**
     * Trusts only the CA whose SHA-256 fingerprint came from the setup link.
     * The server sends that certificate in its chain; it becomes the only
     * trust anchor and the rest of the chain is checked against it with the
     * platform's normal PKIX validation. PKIX doesn't check a trust anchor
     * itself, so the anchor's validity and that the server's certificate
     * isn't a CA are checked here.
     *
     * In a handshake, the server's certificate must also be for the host
     * connected to, before the handshake goes on: with TLS 1.3 the client
     * certificate is sent right after this check, and the HTTP client
     * verifies the host name only after the handshake. Done here rather than
     * by the platform's endpoint identification, whose socket-aware checks
     * may also apply Certificate Transparency, which a private CA can't meet.
     */
    // Lint warns about custom trust managers; this one only picks the trust
    // anchor, adds checks, and leaves the validation to the platform's
    // implementation.
    @SuppressLint("CustomX509TrustManager")
    class PinnedTrustManager(fingerprintHex: String) : X509ExtendedTrustManager() {
        private val fingerprint = Hex.decode(fingerprintHex)

        /** The chain alone, without a host name; [checkServerTrusted] with a socket or engine adds it. */
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            if (chain.isNullOrEmpty()) throw CertificateException("The server sent no certificates")
            val anchor = chain.firstOrNull {
                MessageDigest.getInstance("SHA-256").digest(it.encoded).contentEquals(fingerprint)
            } ?: throw CertificateException("The server's certificate chain doesn't contain the CA from the setup link")
            if (anchor.basicConstraints < 0) {
                throw CertificateException("The certificate from the setup link is not a CA certificate")
            }
            if (chain[0].basicConstraints >= 0) {
                throw CertificateException("The server's certificate is a CA certificate")
            }
            // Throws CertificateExpiredException or CertificateNotYetValidException.
            anchor.checkValidity()
            val anchors = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null)
                setCertificateEntry("anchor", anchor)
            }
            val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            factory.init(anchors)
            val delegate = factory.trustManagers.filterIsInstance<X509TrustManager>().first()
            delegate.checkServerTrusted(chain, authType)
        }

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) {
            checkServerTrusted(chain, authType)
            checkHost(chain!![0], (socket as? SSLSocket)?.handshakeSession)
        }

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) {
            checkServerTrusted(chain, authType)
            checkHost(chain!![0], engine?.handshakeSession)
        }

        private fun checkHost(certificate: X509Certificate, session: SSLSession?) {
            val host = session?.peerHost ?: throw CertificateException("No host name to check the server's certificate against")
            if (!Hostnames.matches(host, certificate)) {
                throw CertificateException("The server's certificate isn't for $host")
            }
        }

        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) =
            throw CertificateException("Not used for client certificates")

        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) =
            throw CertificateException("Not used for client certificates")

        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) =
            throw CertificateException("Not used for client certificates")

        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    /**
     * Creates sockets that speak TLS 1.3 only, as the server does. With
     * TLS 1.2 the client certificate (the username and the device's ID)
     * would go over the wire unencrypted.
     */
    private class Tls13SocketFactory(private val factory: SSLSocketFactory) : SSLSocketFactory() {
        private fun Socket.tls13(): Socket = apply {
            (this as? SSLSocket)?.enabledProtocols = arrayOf(TLS_1_3)
        }

        override fun getDefaultCipherSuites(): Array<String> = factory.defaultCipherSuites

        override fun getSupportedCipherSuites(): Array<String> = factory.supportedCipherSuites

        override fun createSocket(): Socket = factory.createSocket().tls13()

        override fun createSocket(socket: Socket?, host: String?, port: Int, autoClose: Boolean): Socket =
            factory.createSocket(socket, host, port, autoClose).tls13()

        override fun createSocket(host: String?, port: Int): Socket = factory.createSocket(host, port).tls13()

        override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket =
            factory.createSocket(host, port, localHost, localPort).tls13()

        override fun createSocket(host: InetAddress?, port: Int): Socket = factory.createSocket(host, port).tls13()

        override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
            factory.createSocket(address, port, localAddress, localPort).tls13()
    }

    /** Presents [credential] whenever the server asks for a client certificate. */
    private class CredentialKeyManager(private val credential: ClientCredential) : X509ExtendedKeyManager() {
        override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?) = arrayOf(ALIAS)

        override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?) =
            ALIAS

        override fun chooseEngineClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?) =
            ALIAS

        override fun getCertificateChain(alias: String?) =
            if (alias == ALIAS) credential.chain.toTypedArray() else null

        override fun getPrivateKey(alias: String?) = if (alias == ALIAS) credential.privateKey else null

        override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?) = null

        override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?) = null

        private companion object {
            const val ALIAS = "device"
        }
    }

    private const val TLS_1_3 = "TLSv1.3"

    /**
     * A TLS context trusting [fingerprintHex], optionally presenting
     * [credential]. Its session cache is its own, so sessions are never
     * shared with another context. Connect with [socketFactory], which
     * limits the protocol to TLS 1.3.
     */
    fun context(fingerprintHex: String, credential: ClientCredential?): SSLContext =
        SSLContext.getInstance("TLS").apply {
            init(
                credential?.let { arrayOf(CredentialKeyManager(it)) },
                arrayOf(PinnedTrustManager(fingerprintHex)),
                null,
            )
        }

    /** Sockets of [context] that speak TLS 1.3 only. */
    fun socketFactory(context: SSLContext): SSLSocketFactory = Tls13SocketFactory(context.socketFactory)
}

/**
 * Whether a server certificate is for a host: the subject alternative
 * names only (RFC 6125, no fallback to the common name), with a wildcard
 * only as the whole leftmost label, matching exactly one label.
 */
object Hostnames {
    fun matches(host: String, certificate: X509Certificate): Boolean {
        val names = try {
            certificate.subjectAlternativeNames ?: return false
        } catch (e: CertificateParsingException) {
            return false
        }
        val address = ipLiteral(host)
        return names.any { entry ->
            val type = entry.getOrNull(0) as? Int
            val value = entry.getOrNull(1) as? String ?: return@any false
            when {
                address != null -> type == IP_ADDRESS && ipLiteral(value) == address
                type == DNS_NAME -> dnsMatches(normalize(host), normalize(value))
                else -> false
            }
        }
    }

    private const val DNS_NAME = 2
    private const val IP_ADDRESS = 7

    private fun normalize(name: String) = name.lowercase().removeSuffix(".")

    private fun dnsMatches(host: String, pattern: String): Boolean {
        if (host.isEmpty() || pattern.isEmpty()) return false
        if (!pattern.startsWith("*.")) return host == pattern
        val suffix = pattern.substring(1)
        // "*.example.org", not "*.org"; and not "*" elsewhere in the pattern.
        if (suffix.count { it == '.' } < 2 || suffix.contains('*')) return false
        val label = host.substringBefore('.', "")
        return label.isNotEmpty() && host.length == label.length + suffix.length && host.endsWith(suffix)
    }

    /** The address of an IP literal (IPv6 possibly in brackets), or null for a host name; never looks anything up. */
    private fun ipLiteral(text: String): InetAddress? {
        val bare = text.removeSurrounding("[", "]")
        val ipv4 = Regex("""\d{1,3}(\.\d{1,3}){3}""")
        val ipv6 = Regex("""[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*""")
        val isIpv4 = ipv4.matches(bare) && bare.split('.').all { it.toInt() <= 255 }
        if (!isIpv4 && !ipv6.matches(bare)) return null
        return try {
            InetAddress.getByName(bare)
        } catch (e: Exception) {
            null
        }
    }
}

object Hex {
    fun encode(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    fun decode(text: String): ByteArray {
        require(text.length % 2 == 0) { "Odd hex length" }
        return ByteArray(text.length / 2) { i ->
            text.substring(2 * i, 2 * i + 2).toInt(16).toByte()
        }
    }
}
