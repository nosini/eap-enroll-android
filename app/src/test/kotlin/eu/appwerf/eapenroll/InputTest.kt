package eu.appwerf.eapenroll

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
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
