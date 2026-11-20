package eu.appwerf.eapenroll

import java.io.ByteArrayOutputStream
import java.math.BigInteger

/** Minimal DER encoder and reader: what PKCS#10 requests and PKCS#7 certs-only need. */
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

    /** One TLV inside [data]: the tag, and where its encoding and content start and end. */
    class Element(val data: ByteArray, val tag: Int, val start: Int, val contentStart: Int, val end: Int) {
        val isConstructed get() = tag and 0x20 != 0

        fun encoded(): ByteArray = data.copyOfRange(start, end)

        fun content(): ByteArray = data.copyOfRange(contentStart, end)

        /** The elements inside a constructed element. */
        fun children(): List<Element> {
            require(isConstructed) { "DER element with tag $tag is not constructed" }
            val result = ArrayList<Element>()
            var pos = contentStart
            while (pos < end) {
                val child = read(data, pos, end)
                result.add(child)
                pos = child.end
            }
            return result
        }
    }

    /** Reads the single element that makes up all of [data]. */
    fun parse(data: ByteArray): Element {
        val element = read(data, 0, data.size)
        require(element.end == data.size) { "Trailing data after DER element" }
        return element
    }

    /**
     * Reads one element at [offset] that has to end at or before [limit].
     * Only single-byte tags and definite lengths, as DER requires.
     */
    fun read(data: ByteArray, offset: Int, limit: Int): Element {
        require(offset in 0 until limit && limit <= data.size) { "Truncated DER" }
        val tag = data[offset].toInt() and 0xff
        require(tag and 0x1f != 0x1f) { "Multi-byte DER tags are not supported" }
        var pos = offset + 1
        require(pos < limit) { "Truncated DER" }
        val first = data[pos++].toInt() and 0xff
        val length: Int
        if (first < 0x80) {
            length = first
        } else {
            val count = first and 0x7f
            require(count in 1..3) { "Unsupported DER length" }
            require(pos + count <= limit) { "Truncated DER" }
            var value = 0
            repeat(count) { value = (value shl 8) or (data[pos++].toInt() and 0xff) }
            require(value >= 0x80 && value ushr (8 * (count - 1)) != 0) { "Non-minimal DER length" }
            length = value
        }
        require(length <= limit - pos) { "Truncated DER" }
        return Element(data, tag, offset, pos, pos + length)
    }
}
