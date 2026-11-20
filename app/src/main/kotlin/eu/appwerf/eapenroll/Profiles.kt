package eu.appwerf.eapenroll

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import org.json.JSONArray
import org.json.JSONObject

/** JSON form of [WifiProfile], as the server sends it and as the app stores it. */
object Profiles {
    fun parse(body: ByteArray): WifiProfile = fromJson(JSONObject(String(body, Charsets.UTF_8)))

    fun fromJson(json: JSONObject): WifiProfile {
        // Not trimmed: leading and trailing spaces are valid in an SSID.
        val ssid = json.getString("ssid")
        require(ssid.isNotEmpty() && ssid.toByteArray(Charsets.UTF_8).size <= 32) { "Invalid SSID in Wi-Fi profile" }
        val domain = Input.normalizeDomain(json.getString("server_domain"))
        val array = json.getJSONArray("server_ca_certificates")
        val factory = CertificateFactory.getInstance("X.509")
        val certs = (0 until array.length()).map {
            val der = Base64.getDecoder().decode(array.getString(it))
            factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        }
        require(certs.isNotEmpty()) { "Wi-Fi profile has no server CA certificate" }
        certs.forEach {
            require(it.basicConstraints >= 0) { "Not a CA certificate in Wi-Fi profile: ${it.subjectX500Principal}" }
        }
        return WifiProfile(ssid, domain, certs)
    }

    fun toJson(profile: WifiProfile): JSONObject = JSONObject().apply {
        put("ssid", profile.ssid)
        put("server_domain", profile.serverDomain)
        put("server_ca_certificates", JSONArray().apply {
            profile.serverCaCertificates.forEach { put(Base64.getEncoder().encodeToString(it.encoded)) }
        })
    }
}
