package eu.appwerf.eapenroll

import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.text.SimpleDateFormat
import java.util.Date
import java.util.TimeZone

/** Builds small EC certificates for tests, with the app's own DER encoder. */
object TestPki {
    class Issuer(val cert: X509Certificate, val keyPair: KeyPair)

    fun keyPair(curve: String = "secp256r1"): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec(curve)) }.generateKeyPair()

    fun root(
        name: String,
        notBefore: Date = Date(System.currentTimeMillis() - 3_600_000),
        notAfter: Date = Date(System.currentTimeMillis() + 86_400_000),
    ): Issuer {
        val keys = keyPair()
        return Issuer(certificate(name, keys, name, keys, ca = true, notBefore = notBefore, notAfter = notAfter), keys)
    }

    fun intermediate(parent: Issuer, name: String): Issuer {
        val keys = keyPair()
        return Issuer(certificate(name, keys, parent.cert.subjectCn(), parent.keyPair, ca = true), keys)
    }

    fun leaf(
        parent: Issuer,
        name: String,
        keys: KeyPair = keyPair(),
        notBefore: Date = Date(System.currentTimeMillis() - 3_600_000),
        notAfter: Date = Date(System.currentTimeMillis() + 86_400_000),
        serverAuth: Boolean = false,
        /** Subject alternative names of a server certificate: host names or IP addresses. */
        altNames: List<String> = listOf(name),
    ): X509Certificate =
        certificate(name, keys, parent.cert.subjectCn(), parent.keyPair, false, notBefore, notAfter, serverAuth, altNames)

    private fun X509Certificate.subjectCn() = Certs.commonName(this)

    private fun name(cn: String) = Der.sequence(
        Der.set(Der.sequence(Der.oid("2.5.4.3"), Der.utf8String(cn))),
    )

    private fun time(date: Date): ByteArray {
        val format = SimpleDateFormat("yyyyMMddHHmmss'Z'").apply { timeZone = TimeZone.getTimeZone("UTC") }
        return Der.tlv(0x18, format.format(date).toByteArray())
    }

    private fun extension(oid: String, critical: Boolean, value: ByteArray) = Der.sequence(
        Der.oid(oid),
        *(if (critical) arrayOf(Der.tlv(0x01, byteArrayOf(0xff.toByte()))) else emptyArray()),
        Der.tlv(0x04, value),
    )

    private fun certificate(
        subject: String,
        subjectKeys: KeyPair,
        issuer: String,
        issuerKeys: KeyPair,
        ca: Boolean,
        notBefore: Date = Date(System.currentTimeMillis() - 3_600_000),
        notAfter: Date = Date(System.currentTimeMillis() + 86_400_000),
        serverAuth: Boolean = false,
        altNames: List<String> = emptyList(),
    ): X509Certificate {
        val algorithm = Der.sequence(Der.oid("1.2.840.10045.4.3.2"))
        val extensions = ArrayList<ByteArray>()
        if (ca) {
            extensions += extension("2.5.29.19", true, Der.sequence(Der.tlv(0x01, byteArrayOf(0xff.toByte()))))
            extensions += extension("2.5.29.15", true, Der.bitString(byteArrayOf(0x06)))
        } else {
            extensions += extension("2.5.29.19", true, Der.sequence())
            val eku = if (serverAuth) "1.3.6.1.5.5.7.3.1" else "1.3.6.1.5.5.7.3.2"
            extensions += extension("2.5.29.37", false, Der.sequence(Der.oid(eku)))
            if (serverAuth) {
                val names = altNames.map {
                    // iPAddress for a literal, otherwise dNSName.
                    if (it.contains(':') || it.matches(Regex("""[0-9.]+"""))) {
                        Der.tlv(0x87, java.net.InetAddress.getByName(it).address)
                    } else {
                        Der.tlv(0x82, it.toByteArray())
                    }
                }
                extensions += extension("2.5.29.17", false, Der.sequence(*names.toTypedArray()))
            }
        }
        val tbs = Der.sequence(
            Der.contextConstructed(0, Der.integer(BigInteger.TWO)),
            Der.integer(BigInteger(64, SecureRandom()).add(BigInteger.ONE)),
            algorithm,
            name(issuer),
            Der.sequence(time(notBefore), time(notAfter)),
            name(subject),
            subjectKeys.public.encoded,
            Der.contextConstructed(3, Der.sequence(*extensions.toTypedArray())),
        )
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(issuerKeys.private)
            update(tbs)
            sign()
        }
        val der = Der.sequence(tbs, algorithm, Der.bitString(signature))
        return CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate
    }

    /** A certs-only PKCS#7 SignedData, as an EST server sends it. */
    fun certsOnly(certs: List<X509Certificate>): ByteArray = Der.sequence(
        Der.oid("1.2.840.113549.1.7.2"),
        Der.contextConstructed(
            0,
            Der.sequence(
                Der.integer(BigInteger.ONE),
                Der.set(),
                Der.sequence(Der.oid("1.2.840.113549.1.7.1")),
                Der.contextConstructed(0, *certs.map { it.encoded }.toTypedArray()),
                Der.set(),
            ),
        ),
    )
}
