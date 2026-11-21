package eu.appwerf.eapenroll

import android.annotation.SuppressLint
import java.net.Socket
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedKeyManager
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
     * platform's normal PKIX validation.
     */
    // Lint warns about custom trust managers; this one only picks the trust
    // anchor and leaves the validation to the platform's implementation.
    @SuppressLint("CustomX509TrustManager")
    class PinnedTrustManager(fingerprintHex: String) : X509TrustManager {
        private val fingerprint = Hex.decode(fingerprintHex)

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            if (chain.isNullOrEmpty()) throw CertificateException("The server sent no certificates")
            val anchor = chain.firstOrNull {
                MessageDigest.getInstance("SHA-256").digest(it.encoded).contentEquals(fingerprint)
            } ?: throw CertificateException("The server's certificate chain doesn't contain the CA from the setup link")
            if (anchor.basicConstraints < 0) {
                throw CertificateException("The certificate from the setup link is not a CA certificate")
            }
            val anchors = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null)
                setCertificateEntry("anchor", anchor)
            }
            val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            factory.init(anchors)
            val delegate = factory.trustManagers.filterIsInstance<X509TrustManager>().first()
            delegate.checkServerTrusted(chain, authType)
        }

        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) =
            throw CertificateException("Not used for client certificates")

        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
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

    /**
     * A TLS context trusting [fingerprintHex], optionally presenting
     * [credential]. Its session cache is its own, so sessions are never
     * shared with another context. The protocol version is left to the
     * platform; the server only accepts TLS 1.3.
     */
    fun context(fingerprintHex: String, credential: ClientCredential?): SSLContext =
        SSLContext.getInstance("TLS").apply {
            init(
                credential?.let { arrayOf(CredentialKeyManager(it)) },
                arrayOf(PinnedTrustManager(fingerprintHex)),
                null,
            )
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
