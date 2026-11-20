package eu.appwerf.eapenroll

import java.io.File
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CsrTest {
    private class Tlv(val tag: Int, val start: Int, val contentStart: Int, val end: Int)

    private fun readTlv(data: ByteArray, offset: Int): Tlv {
        val tag = data[offset].toInt() and 0xff
        var pos = offset + 1
        var length = data[pos++].toInt() and 0xff
        if (length >= 0x80) {
            val count = length and 0x7f
            length = 0
            repeat(count) { length = (length shl 8) or (data[pos++].toInt() and 0xff) }
        }
        return Tlv(tag, offset, pos, pos + length)
    }

    private fun children(data: ByteArray, parent: Tlv): List<Tlv> {
        val result = ArrayList<Tlv>()
        var pos = parent.contentStart
        while (pos < parent.end) {
            val child = readTlv(data, pos)
            result.add(child)
            pos = child.end
        }
        return result
    }

    private fun check(curve: String, algorithm: String, oid: String) {
        val keyPair = KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec(curve)) }
            .generateKeyPair()
        val csr = Csr.create(keyPair, "user.name")

        val outer = readTlv(csr, 0)
        assertEquals(0x30, outer.tag)
        assertEquals(csr.size, outer.end)
        val (info, algId, sig) = children(csr, outer)

        assertArrayEquals(Der.sequence(Der.oid(oid)), csr.copyOfRange(algId.start, algId.end))

        val infoFields = children(csr, info)
        assertEquals(4, infoFields.size)
        assertArrayEquals(
            keyPair.public.encoded,
            csr.copyOfRange(infoFields[2].start, infoFields[2].end),
        )
        assertEquals(0xa0, infoFields[3].tag)

        assertEquals(0x03, sig.tag)
        assertEquals(0, csr[sig.contentStart].toInt())
        val verifier = Signature.getInstance(algorithm)
        verifier.initVerify(keyPair.public)
        verifier.update(csr, info.start, info.end - info.start)
        assertTrue(verifier.verify(csr.copyOfRange(sig.contentStart + 1, sig.end)))

        // Leave a PEM copy for an openssl cross-check (`openssl req -verify`).
        val out = File("build/test-csr/$curve.csr")
        out.parentFile!!.mkdirs()
        out.writeText(Pem.encode("CERTIFICATE REQUEST", csr))
    }

    @Test
    fun p384UsesSha384() = check("secp384r1", "SHA384withECDSA", "1.2.840.10045.4.3.3")

    @Test
    fun p256UsesSha256() = check("secp256r1", "SHA256withECDSA", "1.2.840.10045.4.3.2")

    @Test
    fun oidEncoding() {
        assertArrayEquals(byteArrayOf(0x06, 0x03, 0x55, 0x04, 0x03), Der.oid("2.5.4.3"))
        assertArrayEquals(
            byteArrayOf(0x06, 0x08, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x04, 0x03, 0x03),
            Der.oid("1.2.840.10045.4.3.3"),
        )
    }

    @Test
    fun longFormLength() {
        val encoded = Der.tlv(0x04, ByteArray(300))
        assertArrayEquals(byteArrayOf(0x04, 0x82.toByte(), 0x01, 0x2c), encoded.copyOfRange(0, 4))
        assertEquals(304, encoded.size)
    }
}
