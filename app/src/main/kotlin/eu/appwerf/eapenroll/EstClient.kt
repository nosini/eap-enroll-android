package eu.appwerf.eapenroll

import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.IOException
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URL
import java.security.cert.X509Certificate
import java.util.Base64
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext

/**
 * An error answer from the enrollment server. [message] is the server's
 * text, meant for logs. [reason] is the machine-readable reason from the
 * `Enroll-Error` header (for example `user_disabled`), if the server sent one.
 */
class EstException(
    val status: Int,
    message: String,
    val retryAfterSeconds: Long? = null,
    val reason: String? = null,
) : IOException("HTTP $status${reason?.let { " ($it)" }.orEmpty()}: $message")

/** The Wi-Fi network the certificates are for, from `wifi/profile`. */
data class WifiProfile(
    val ssid: String,
    val serverDomain: String,
    val serverCaCertificates: List<X509Certificate>,
)

/**
 * EST client for the enrollment server (see the server's docs/protocol.md).
 * Without [credential] only the unauthenticated requests work.
 *
 * Use one client per credential and [close] it when switching to a renewed
 * one. After a new device credential has been stored, presenting the old
 * one makes the server disable the device as if the credential had been
 * copied, so nothing may carry the old certificate:
 *
 * - Each client has its own SSLContext, so its TLS sessions are never
 *   resumed by another client, and [close] makes it refuse further
 *   requests. Connections are TLS 1.3 only, where a session can only be
 *   resumed with a ticket from the server, and the server sends none.
 * - Every request asks for `Connection: close`, so no connection stays in
 *   the platform's pool after its answer.
 * - The credential is offered only on the requests that need it, never on
 *   `cacerts` or `device/simpleenroll`: the server checks a client
 *   certificate in the handshake, and an expired one would fail even the
 *   setup with a new code.
 */
class EstClient(
    serverUrl: String,
    private val caFingerprint: String,
    private val credential: ClientCredential? = null,
) : Closeable {
    private val base = SetupUri.normalizeServerUrl(serverUrl) + "/.well-known/est/"
    private val anonymous: SSLContext = EstTls.context(caFingerprint, null)
    private val authenticated: SSLContext? = credential?.let { EstTls.context(caFingerprint, it) }
    private val anonymousSockets = EstTls.socketFactory(anonymous)
    private val authenticatedSockets = authenticated?.let(EstTls::socketFactory)

    @Volatile
    private var closed = false

    /**
     * Device credential for the Keystore key in [csr], authorized by the
     * one-time [code]. [attestation] is the key's attestation chain (DER,
     * leaf first), generated with SHA-256 of [code] as the challenge.
     */
    fun enrollDevice(code: String, csr: ByteArray, attestation: List<ByteArray>? = null): List<X509Certificate> =
        certificates(
            post("device/simpleenroll", PKCS10, encodeCsr(csr), bearer = code, headers = attestationHeaders(attestation), withCredential = false),
        )

    /**
     * New device credential; authenticated with the current one.
     * [attestation] is the new key's attestation chain, generated with
     * SHA-256 of the current credential's certificate as the challenge.
     */
    fun reenrollDevice(csr: ByteArray, attestation: List<ByteArray>? = null): List<X509Certificate> =
        certificates(post("device/simplereenroll", PKCS10, encodeCsr(csr), headers = attestationHeaders(attestation)))

    /** Wi-Fi certificate for the (new) key in [csr]. */
    fun enrollWifi(csr: ByteArray): List<X509Certificate> =
        certificates(post("wifi/simpleenroll", PKCS10, encodeCsr(csr)))

    /** Tells the server that Wi-Fi works with the certificate [serial], so it revokes older ones. */
    fun confirmWifi(serial: BigInteger) {
        val response = post("wifi/confirm", "text/plain", serial.toString(16).toByteArray())
        if (response.status != HttpURLConnection.HTTP_NO_CONTENT && response.status != HttpURLConnection.HTTP_OK) {
            throw EstException(response.status, "unexpected answer to wifi/confirm")
        }
    }

    /**
     * The Wi-Fi network settings, or null if the server has none (404).
     * Throws [IllegalArgumentException] for a malformed profile.
     */
    fun wifiProfile(): WifiProfile? {
        val response = request("GET", "wifi/profile", null, null, null, allowNotFound = true)
            ?: return null
        if (response.status != HttpURLConnection.HTTP_OK) {
            throw IOException("Unexpected answer to wifi/profile: HTTP ${response.status}")
        }
        val type = response.contentType?.substringBefore(';')?.trim()?.lowercase()
        if (type != "application/json") {
            throw IOException("Unexpected response type ${response.contentType} for wifi/profile")
        }
        return Profiles.parse(response.body)
    }

    fun wifiCaCertificates(): List<X509Certificate> =
        certificates(request("GET", "wifi/cacerts", null, null, null, withCredential = false)!!)

    /**
     * Later requests throw. Its connections aren't pooled, so none is left
     * open. Invalidating the cached TLS sessions is only a precaution:
     * Android's session cache lists no session IDs, so it does nothing
     * there, and the context isn't used again anyway.
     */
    override fun close() {
        closed = true
        listOfNotNull(anonymous, authenticated).forEach { context ->
            val sessions = context.clientSessionContext ?: return@forEach
            sessions.ids.toList().forEach { sessions.getSession(it)?.invalidate() }
        }
    }

    private class Response(val status: Int, val contentType: String?, val body: ByteArray)

    private fun post(
        path: String,
        contentType: String,
        body: ByteArray,
        bearer: String? = null,
        headers: Map<String, String> = emptyMap(),
        withCredential: Boolean = true,
    ): Response = request("POST", path, contentType, body, bearer, headers = headers, withCredential = withCredential)!!

    private fun attestationHeaders(chain: List<ByteArray>?): Map<String, String> =
        chain?.let { mapOf("Key-Attestation" to attestationHeader(it)) } ?: emptyMap()

    private fun request(
        method: String,
        path: String,
        contentType: String?,
        body: ByteArray?,
        bearer: String?,
        allowNotFound: Boolean = false,
        headers: Map<String, String> = emptyMap(),
        withCredential: Boolean = true,
    ): Response? {
        check(!closed) { "This client was closed; its credential may have been replaced" }
        val sockets = if (withCredential) authenticatedSockets ?: anonymousSockets else anonymousSockets
        val connection = URL(base + path).openConnection() as HttpsURLConnection
        try {
            connection.sslSocketFactory = sockets
            connection.connectTimeout = TIMEOUT_MS
            connection.readTimeout = TIMEOUT_MS
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.requestMethod = method
            connection.setRequestProperty("Accept", "*/*")
            // Not kept alive: a pooled connection keeps the client
            // certificate of its handshake.
            connection.setRequestProperty("Connection", "close")
            bearer?.let { connection.setRequestProperty("Authorization", "Bearer $it") }
            headers.forEach { (name, value) -> connection.setRequestProperty(name, value) }
            if (body != null) {
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", contentType)
                connection.setFixedLengthStreamingMode(body.size)
                connection.outputStream.use { it.write(body) }
            }
            val status = connection.responseCode
            if (status == HttpURLConnection.HTTP_NOT_FOUND && allowNotFound) {
                return null
            }
            if (status !in 200..299) {
                // Only the first line is used; a large error page mustn't
                // hide the status and the headers.
                val text = connection.errorStream?.use { Streams.readPrefix(it, MAX_ERROR_TEXT) }
                    ?.toString(Charsets.UTF_8)?.lineSequence()?.firstOrNull()?.take(200).orEmpty()
                // A zero or negative wait is no instruction; the app then
                // uses its own default.
                val retryAfter = connection.getHeaderField("Retry-After")?.trim()?.toLongOrNull()?.takeIf { it > 0 }
                val reason = connection.getHeaderField("Enroll-Error")?.trim()?.takeIf { reasonPattern.matches(it) }
                throw EstException(status, text.ifEmpty { connection.responseMessage ?: "error" }, retryAfter, reason)
            }
            val responseBody = if (status == HttpURLConnection.HTTP_NO_CONTENT) {
                ByteArray(0)
            } else {
                connection.inputStream.use { Streams.readLimited(it, MAX_RESPONSE, "The response") }
            }
            return Response(status, connection.contentType, responseBody)
        } finally {
            connection.disconnect()
        }
    }

    private fun certificates(response: Response): List<X509Certificate> {
        val type = response.contentType?.substringBefore(';')?.trim()?.lowercase()
        if (type != "application/pkcs7-mime") {
            throw IOException("Unexpected response type ${response.contentType}")
        }
        return Pkcs7.fromEstBody(response.body)
    }


    private fun encodeCsr(der: ByteArray): ByteArray = Base64.getEncoder().encode(der)

    companion object {
        private const val PKCS10 = "application/pkcs10"
        private const val TIMEOUT_MS = 30_000
        private const val MAX_RESPONSE = 256 * 1024
        private const val MAX_ERROR_TEXT = 4096
        private val reasonPattern = Regex("[a-z0-9_]{1,64}")

        /** The `Key-Attestation` header: standard base64, one line, of the concatenated DER certificates. */
        fun attestationHeader(chain: List<ByteArray>): String {
            require(chain.isNotEmpty()) { "Empty attestation chain" }
            val all = ByteArrayOutputStream()
            chain.forEach { all.write(it) }
            return Base64.getEncoder().encodeToString(all.toByteArray())
        }
    }
}
