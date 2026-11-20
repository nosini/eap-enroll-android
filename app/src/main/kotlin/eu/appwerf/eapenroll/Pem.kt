package eu.appwerf.eapenroll

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

object Pem {
    fun encode(type: String, der: ByteArray): String {
        val body = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der)
        return "-----BEGIN $type-----\n$body\n-----END $type-----\n"
    }

    fun encodeChain(certs: List<X509Certificate>): String =
        certs.joinToString("") { encode("CERTIFICATE", it.encoded) }

    /** Parses one or more PEM (or DER) certificates, in file order. */
    fun certificates(data: ByteArray): List<X509Certificate> {
        val factory = CertificateFactory.getInstance("X.509")
        val certs = factory.generateCertificates(ByteArrayInputStream(data))
            .map { it as X509Certificate }
        require(certs.isNotEmpty()) { "No certificates found" }
        return certs
    }
}
