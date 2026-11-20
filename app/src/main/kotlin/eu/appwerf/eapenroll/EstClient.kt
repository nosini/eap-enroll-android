package eu.appwerf.eapenroll

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URL
import java.security.cert.X509Certificate
import java.util.Base64
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocketFactory

/** An error answer from the enrollment server. [message] is the server's text, meant for logs. */
class EstException(val status: Int, message: String, val retryAfterSeconds: Long? = null) :
    IOException("HTTP $status: $message")

/** The Wi-Fi network the certificates are for, from `wifi/profile`. */
data class WifiProfile(
    val ssid: String,
    val serverDomain: String,
    val serverCaCertificates: List<X509Certificate>,
)

/**
 * EST client for the enrollment server (see the server's docs/protocol.md).
 * Without [credential] only the unauthenticated requests work.
 */
class EstClient(
    serverUrl: String,
    private val caFingerprint: String,
    private val credential: ClientCredential? = null,
) {
    private val base = SetupUri.normalizeServerUrl(serverUrl) + "/.well-known/est/"
    private val socketFactory: SSLSocketFactory = EstTls.socketFactory(caFingerprint, credential)

    /** Device credential for the Keystore key in [csr], authorized by the one-time [code]. */
    fun enrollDevice(code: String, csr: ByteArray): List<X509Certificate> =
        certificates(post("device/simpleenroll", PKCS10, encodeCsr(csr), bearer = code))

    /** New device credential; authenticated with the current one. */
    fun reenrollDevice(csr: ByteArray): List<X509Certificate> =
        certificates(post("device/simplereenroll", PKCS10, encodeCsr(csr)))

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

    /** The Wi-Fi network settings, or null if the server has none (404). */
    fun wifiProfile(): WifiProfile? {
        val response = request("GET", "wifi/profile", null, null, null, allowNotFound = true)
            ?: return null
        return Profiles.parse(response.body)
    }

    fun wifiCaCertificates(): List<X509Certificate> = certificates(request("GET", "wifi/cacerts", null, null, null)!!)

    private class Response(val status: Int, val contentType: String?, val body: ByteArray)

    private fun post(path: String, contentType: String, body: ByteArray, bearer: String? = null): Response =
        request("POST", path, contentType, body, bearer)!!

    private fun request(
        method: String,
        path: String,
        contentType: String?,
        body: ByteArray?,
        bearer: String?,
        allowNotFound: Boolean = false,
    ): Response? {
        val connection = URL(base + path).openConnection() as HttpsURLConnection
        try {
            connection.sslSocketFactory = socketFactory
            connection.connectTimeout = TIMEOUT_MS
            connection.readTimeout = TIMEOUT_MS
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.requestMethod = method
            connection.setRequestProperty("Accept", "*/*")
            bearer?.let { connection.setRequestProperty("Authorization", "Bearer $it") }
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
                val text = connection.errorStream?.let { readLimited(it) }
                    ?.toString(Charsets.UTF_8)?.lineSequence()?.firstOrNull()?.take(200).orEmpty()
                val retryAfter = connection.getHeaderField("Retry-After")?.trim()?.toLongOrNull()
                throw EstException(status, text.ifEmpty { connection.responseMessage ?: "error" }, retryAfter)
            }
            val responseBody = if (status == HttpURLConnection.HTTP_NO_CONTENT) {
                ByteArray(0)
            } else {
                connection.inputStream.use { readLimited(it) }
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

    private fun readLimited(input: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val n = input.read(buffer)
            if (n < 0) break
            out.write(buffer, 0, n)
            if (out.size() > MAX_RESPONSE) throw IOException("Response too large")
        }
        return out.toByteArray()
    }

    private fun encodeCsr(der: ByteArray): ByteArray = Base64.getEncoder().encode(der)

    private companion object {
        const val PKCS10 = "application/pkcs10"
        const val TIMEOUT_MS = 30_000
        const val MAX_RESPONSE = 256 * 1024
    }
}
