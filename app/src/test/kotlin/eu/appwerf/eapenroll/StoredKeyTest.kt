package eu.appwerf.eapenroll

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class StoredKeyTest {
    private val key = StoredKey("wifi-key-wrap-1", ByteArray(12) { 1 }, ByteArray(150) { 2 }, ByteArray(91) { 3 })

    @Test
    fun roundTrip() {
        val read = StoredKey.decode(key.encode())
        assertEquals(key.alias, read.alias)
        assertArrayEquals(key.iv, read.iv)
        assertArrayEquals(key.ciphertext, read.ciphertext)
        assertArrayEquals(key.publicKey, read.publicKey)
    }

    @Test
    fun rejectsIncompleteFiles() {
        val encoded = key.encode()
        for (bad in listOf(ByteArray(0), byteArrayOf(2) + encoded.copyOfRange(1, encoded.size), encoded.copyOf(encoded.size - 1), encoded + 0)) {
            assertThrows(IllegalArgumentException::class.java) { StoredKey.decode(bad) }
        }
    }
}
