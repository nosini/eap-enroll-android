package eu.appwerf.eapenroll

import java.io.ByteArrayInputStream
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

/**
 * JSON form of [WifiProfile], as the server sends it and as the app stores
 * it. Anything malformed throws [IllegalArgumentException].
 *
 * Values are read by type, not with getString(): Android's org.json turns
 * null and numbers into strings there ("null" would pass as an SSID).
 */
object Profiles {
    fun parse(body: ByteArray): WifiProfile = try {
        fromJson(JSONObject(String(body, Charsets.UTF_8)))
    } catch (e: JSONException) {
        throw IllegalArgumentException("The Wi-Fi profile isn't valid JSON: ${e.message}", e)
    }

    fun fromJson(json: JSONObject): WifiProfile {
        // Not trimmed: leading and trailing spaces are valid in an SSID.
        val ssid = json.string("ssid")
        require(ssid.isNotEmpty() && ssid.toByteArray(Charsets.UTF_8).size <= 32) { "Invalid SSID in Wi-Fi profile" }
        val domain = Input.normalizeDomain(json.string("server_domain"))
        val array = json.opt("server_ca_certificates") as? JSONArray
            ?: throw IllegalArgumentException("Wi-Fi profile: server_ca_certificates is missing or not a list")
        val factory = CertificateFactory.getInstance("X.509")
        val certs = (0 until array.length()).map {
            val text = array.opt(it) as? String
                ?: throw IllegalArgumentException("Wi-Fi profile: a server CA certificate is not a string")
            val der = Base64.getDecoder().decode(text)
            require(der.isNotEmpty()) { "Wi-Fi profile: an empty server CA certificate" }
            try {
                factory.generateCertificate(ByteArrayInputStream(der)) as? X509Certificate
            } catch (e: CertificateException) {
                null
            } ?: throw IllegalArgumentException("Wi-Fi profile: a server CA certificate can't be read")
        }
        require(certs.isNotEmpty()) { "Wi-Fi profile has no server CA certificate" }
        certs.forEach {
            require(it.basicConstraints >= 0) { "Not a CA certificate in Wi-Fi profile: ${it.subjectX500Principal}" }
        }
        return WifiProfile(ssid, domain, certs)
    }

    private fun JSONObject.string(name: String): String =
        opt(name) as? String ?: throw IllegalArgumentException("Wi-Fi profile: $name is missing or not a string")

    fun toJson(profile: WifiProfile): JSONObject = JSONObject().apply {
        put("ssid", profile.ssid)
        put("server_domain", profile.serverDomain)
        put("server_ca_certificates", JSONArray().apply {
            profile.serverCaCertificates.forEach { put(Base64.getEncoder().encodeToString(it.encoded)) }
        })
    }
}
