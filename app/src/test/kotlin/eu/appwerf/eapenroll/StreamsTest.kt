package eu.appwerf.eapenroll

import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class StreamsTest {
    /** An endless stream that counts what was read from it. */
    private class Endless : InputStream() {
        var read = 0L

        override fun read(): Int = 0.also { read++ }

        override fun read(b: ByteArray, off: Int, len: Int): Int = len.also { read += it }
    }

    @Test
    fun readLimitedStopsJustPastTheLimit() {
        val data = ByteArray(1000) { it.toByte() }
        assertArrayEquals(data, Streams.readLimited(ByteArrayInputStream(data), 1000))
        val endless = Endless()
        val e = assertThrows(IOException::class.java) { Streams.readLimited(endless, 64 * 1024, "The file") }
        assertEquals("The file is larger than 64 KiB", e.message)
        assertEquals(64 * 1024 + 1L, endless.read)
    }

    @Test
    fun readPrefixReadsNoMore() {
        val endless = Endless()
        assertEquals(4096, Streams.readPrefix(endless, 4096).size)
        assertEquals(4096L, endless.read)
        assertArrayEquals(byteArrayOf(1, 2), Streams.readPrefix(ByteArrayInputStream(byteArrayOf(1, 2)), 4096))
    }
}
