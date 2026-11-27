package eu.appwerf.eapenroll

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class InputTest {
    @Test
    fun normalizesDomain() {
        assertEquals("radius.example.org", Input.normalizeDomain(" Radius.Example.org. "))
        assertEquals("radius.example.org", Input.normalizeDomain("radius. example. org"))
        assertEquals("a-1.example", Input.normalizeDomain("a-1.example"))
    }

    @Test
    fun rejectsInvalidDomains() {
        for (bad in listOf("radius..example.org", "-radius.example.org", "radius_1.example.org",
                "radius.example.org/", "a".repeat(64) + ".org")) {
            assertThrows(IllegalArgumentException::class.java) { Input.normalizeDomain(bad) }
        }
    }
}

class WifiSetupInputTest {
    @Test
    fun refusesSsidsLongerThan32Bytes() {
        val ca = TestPki.root("RADIUS CA")
        val keys = TestPki.keyPair("secp384r1")
        val leaf = TestPki.leaf(ca, "alice", keys)
        // 11 three-byte characters: 33 bytes in 11 characters.
        val settings = NetworkSettings("€".repeat(11), "alice", "radius.example.org", false, listOf(ca.cert))
        val e = assertThrows(IllegalArgumentException::class.java) {
            WifiSetup.suggestion(settings, keys.private, listOf(leaf))
        }
        assertTrue(e.message!!.contains("32 bytes"))
    }
}
