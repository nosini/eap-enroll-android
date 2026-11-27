package eu.appwerf.eapenroll

import java.net.URI
import java.net.URISyntaxException
import java.net.URLDecoder

/**
 * The setup link from the enrollment server's QR code:
 * `eapenroll://setup?v=1&url=<service URL>&ca=<SHA-256 hex>&code=<one-time code>`.
 */
class SetupUri private constructor(
    /** Base URL of the service, `https://host[:port]`, without a trailing slash. */
    val serverUrl: String,
    /** Lower-case hex SHA-256 of the CA certificate the service's TLS chain has to contain. */
    val caFingerprint: String,
    /** One-time code; never log it. */
    val code: String,
) {
    /** Doesn't include the code, so it can be logged. */
    override fun toString() = "SetupUri(url=$serverUrl, ca=$caFingerprint)"

    companion object {
        private val fingerprintPattern = Regex("[0-9a-fA-F]{64}")
        private val codePattern = Regex("[A-Z2-7]{32}")

        fun parse(text: String): SetupUri {
            val uri = try {
                URI(text.trim())
            } catch (e: URISyntaxException) {
                throw IllegalArgumentException("Not a setup link", e)
            }
            require(uri.scheme.equals("eapenroll", ignoreCase = true) &&
                uri.rawAuthority.equals("setup", ignoreCase = true) &&
                uri.rawPath.isNullOrEmpty() && uri.rawFragment == null
            ) { "Not a setup link" }

            val params = HashMap<String, String>()
            for (part in uri.rawQuery.orEmpty().split('&')) {
                if (part.isEmpty()) continue
                val name = decode(part.substringBefore('='))
                val value = decode(part.substringAfter('=', ""))
                require(params.put(name, value) == null) { "Setup link has '$name' twice" }
            }
            val version = params["v"] ?: throw IllegalArgumentException("Setup link has no version")
            require(version == "1") { "Unsupported setup link version $version; update the app" }

            val serverUrl = normalizeServerUrl(
                params["url"] ?: throw IllegalArgumentException("Setup link has no server URL"),
            )
            val ca = params["ca"] ?: throw IllegalArgumentException("Setup link has no CA fingerprint")
            require(fingerprintPattern.matches(ca)) { "Invalid CA fingerprint in setup link" }
            val code = params["code"] ?: throw IllegalArgumentException("Setup link has no code")
            require(codePattern.matches(code)) { "Invalid one-time code in setup link" }
            return SetupUri(serverUrl, ca.lowercase(), code)
        }

        /** Accepts `https://host[:port]` (a lone trailing slash is dropped); anything else throws. */
        fun normalizeServerUrl(text: String): String {
            val uri = try {
                URI(text)
            } catch (e: URISyntaxException) {
                throw IllegalArgumentException("Invalid server URL", e)
            }
            require(uri.scheme.equals("https", ignoreCase = true)) { "The server URL must use https" }
            require(!uri.host.isNullOrEmpty() && uri.rawUserInfo == null &&
                (uri.rawPath.isNullOrEmpty() || uri.rawPath == "/") &&
                uri.rawQuery == null && uri.rawFragment == null
            ) { "The server URL must be https://host[:port]" }
            // Java's URI takes any non-negative int as the port; an
            // impossible one would fail only once the key has been made.
            require(uri.port == -1 || uri.port in 1..65535) { "Invalid port in server URL" }
            val port = if (uri.port == -1) "" else ":${uri.port}"
            return "https://${uri.host.lowercase()}$port"
        }

        private fun decode(text: String): String = URLDecoder.decode(text, "UTF-8")
    }
}
