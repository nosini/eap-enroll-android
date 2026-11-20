package eu.appwerf.eapenroll

import java.io.ByteArrayOutputStream
import java.math.BigInteger

/** Minimal DER encoder: just what a PKCS#10 request needs. */
object Der {
    private const val INTEGER = 0x02
    private const val BIT_STRING = 0x03
    private const val OID = 0x06
    private const val UTF8_STRING = 0x0c
    private const val SEQUENCE = 0x30
    private const val SET = 0x31

    fun tlv(tag: Int, content: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(tag)
        writeLength(out, content.size)
        out.write(content)
        return out.toByteArray()
    }

    private fun writeLength(out: ByteArrayOutputStream, length: Int) {
        if (length < 0x80) {
            out.write(length)
            return
        }
        var bytes = 0
        var rest = length
        while (rest > 0) {
            bytes++
            rest = rest ushr 8
        }
        out.write(0x80 or bytes)
        for (i in bytes - 1 downTo 0) {
            out.write((length ushr (8 * i)) and 0xff)
        }
    }

    private fun concat(parts: Array<out ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        parts.forEach { out.write(it) }
        return out.toByteArray()
    }

    fun sequence(vararg parts: ByteArray) = tlv(SEQUENCE, concat(parts))

    fun set(vararg parts: ByteArray) = tlv(SET, concat(parts))

    fun integer(value: BigInteger) = tlv(INTEGER, value.toByteArray())

    fun utf8String(value: String) = tlv(UTF8_STRING, value.toByteArray(Charsets.UTF_8))

    /** BIT STRING without unused bits. */
    fun bitString(value: ByteArray) = tlv(BIT_STRING, byteArrayOf(0) + value)

    /** Constructed context-specific tag, e.g. [0] for the CSR attributes. */
    fun contextConstructed(number: Int, vararg parts: ByteArray) =
        tlv(0xa0 or number, concat(parts))

    fun oid(dotted: String): ByteArray {
        val arcs = dotted.split('.').map { it.toLong() }
        require(arcs.size >= 2 && arcs[0] in 0..2) { "Invalid OID $dotted" }
        val out = ByteArrayOutputStream()
        writeBase128(out, arcs[0] * 40 + arcs[1])
        arcs.drop(2).forEach { writeBase128(out, it) }
        return tlv(OID, out.toByteArray())
    }

    private fun writeBase128(out: ByteArrayOutputStream, value: Long) {
        require(value >= 0)
        val groups = ArrayList<Int>()
        var rest = value
        do {
            groups.add((rest and 0x7f).toInt())
            rest = rest ushr 7
        } while (rest > 0)
        for (i in groups.indices.reversed()) {
            out.write(if (i > 0) groups[i] or 0x80 else groups[i])
        }
    }
}
