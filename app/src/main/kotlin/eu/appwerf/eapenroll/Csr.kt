package eu.appwerf.eapenroll

import java.math.BigInteger
import java.security.KeyPair
import java.security.Signature
import java.security.interfaces.ECPublicKey

/** Builds a PKCS#10 certification request (RFC 2986) for an EC key. */
object Csr {
    private const val OID_COMMON_NAME = "2.5.4.3"
    private const val OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
    private const val OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3"

    /**
     * Returns the DER-encoded request with subject CN=[commonName].
     * P-384 keys are signed with SHA-384, smaller keys with SHA-256.
     */
    fun create(keyPair: KeyPair, commonName: String): ByteArray {
        require(commonName.isNotBlank()) { "Common name is empty" }
        val publicKey = keyPair.public as? ECPublicKey
            ?: throw IllegalArgumentException("Only EC keys are supported")

        val subject = Der.sequence(
            Der.set(Der.sequence(Der.oid(OID_COMMON_NAME), Der.utf8String(commonName)))
        )
        val info = Der.sequence(
            Der.integer(BigInteger.ZERO),
            subject,
            // X.509 SubjectPublicKeyInfo, as produced by the key itself.
            publicKey.encoded,
            Der.contextConstructed(0),
        )

        val p384 = publicKey.params.curve.field.fieldSize > 256
        val (algorithm, oid) = if (p384) {
            "SHA384withECDSA" to OID_ECDSA_SHA384
        } else {
            "SHA256withECDSA" to OID_ECDSA_SHA256
        }
        val signature = Signature.getInstance(algorithm).run {
            initSign(keyPair.private)
            update(info)
            sign()
        }

        return Der.sequence(
            info,
            Der.sequence(Der.oid(oid)),
            Der.bitString(signature),
        )
    }
}
