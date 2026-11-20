package eu.appwerf.eapenroll

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * Reads the EST "certs-only" response: a PKCS#7 SignedData without content
 * or signers that only carries certificates (RFC 7030 section 4.1.3, RFC
 * 5652). Parsed here rather than with CertificateFactory's PKCS#7 support,
 * which differs between Android versions and the JVM used by the tests.
 */
object Pkcs7 {
    private const val SEQUENCE = 0x30
    private const val SET = 0x31
    private const val INTEGER = 0x02
    private const val OID = 0x06
    private const val CONTEXT_0 = 0xa0
    private const val CONTEXT_1 = 0xa1
    private val OID_SIGNED_DATA = Der.oid("1.2.840.113549.1.7.2")

    /** Decodes an EST response body (base64, line breaks allowed) and returns its certificates in order. */
    fun fromEstBody(body: ByteArray): List<X509Certificate> {
        val text = String(body, Charsets.US_ASCII).filterNot { it.isWhitespace() }
        val der = try {
            Base64.getDecoder().decode(text)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Response is not base64", e)
        }
        return certificates(der)
    }

    /** Returns the certificates of a DER certs-only SignedData, in the order they were sent. */
    fun certificates(der: ByteArray): List<X509Certificate> {
        val contentInfo = Der.parse(der)
        require(contentInfo.tag == SEQUENCE) { "Not a PKCS#7 ContentInfo" }
        val outer = contentInfo.children()
        require(outer.size == 2 && outer[0].tag == OID && outer[0].encoded().contentEquals(OID_SIGNED_DATA)) {
            "Not a PKCS#7 SignedData"
        }
        require(outer[1].tag == CONTEXT_0) { "PKCS#7 content is missing" }
        val wrapped = outer[1].children()
        require(wrapped.size == 1 && wrapped[0].tag == SEQUENCE) { "Malformed SignedData" }

        // version, digestAlgorithms, encapContentInfo, [0] certificates, [1] crls, signerInfos
        val fields = wrapped[0].children()
        require(fields.size >= 4 && fields[0].tag == INTEGER && fields[1].tag == SET && fields[2].tag == SEQUENCE) {
            "Malformed SignedData"
        }
        require(fields.last().tag == SET) { "Malformed SignedData" }
        val optional = fields.subList(3, fields.size - 1)
        require(optional.all { it.tag == CONTEXT_0 || it.tag == CONTEXT_1 }) { "Malformed SignedData" }
        val certs = optional.firstOrNull { it.tag == CONTEXT_0 }
            ?: throw IllegalArgumentException("SignedData has no certificates")

        val factory = CertificateFactory.getInstance("X.509")
        val result = certs.children().map {
            require(it.tag == SEQUENCE) { "Malformed certificate in SignedData" }
            factory.generateCertificate(ByteArrayInputStream(it.encoded())) as X509Certificate
        }
        require(result.isNotEmpty()) { "SignedData has no certificates" }
        return result
    }
}
