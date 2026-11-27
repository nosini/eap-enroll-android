package eu.appwerf.eapenroll

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream

object Streams {
    /** Reads [input] to its end; throws [IOException] as soon as it has more than [limit] bytes. */
    fun readLimited(input: InputStream, limit: Int, what: String = "Data"): ByteArray {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val n = input.read(buffer, 0, minOf(buffer.size, limit + 1 - out.size()))
            if (n < 0) break
            out.write(buffer, 0, n)
            if (out.size() > limit) throw IOException("$what is larger than ${limit / 1024} KiB")
        }
        return out.toByteArray()
    }

    /** The first [limit] bytes of [input] at most; the rest isn't read. */
    fun readPrefix(input: InputStream, limit: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(minOf(8192, limit))
        while (out.size() < limit) {
            val n = input.read(buffer, 0, minOf(buffer.size, limit - out.size()))
            if (n < 0) break
            out.write(buffer, 0, n)
        }
        return out.toByteArray()
    }
}
