package eu.appwerf.eapenroll

import java.util.Date
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Test

/** The certificates the tests build, which they trust to say what they were built with. */
class TestPkiTest {
    @Test
    fun timesAreTheSameInEveryDefaultLocale() {
        val previous = Locale.getDefault()
        try {
            // A locale with another calendar: a formatter that takes the
            // default would write the wrong year.
            Locale.setDefault(Locale.forLanguageTag("th-TH"))
            val notBefore = Date(1_700_000_000_000L)
            val notAfter = Date(notBefore.time + 86_400_000L)
            val cert = TestPki.leaf(TestPki.root("Test CA"), "alice", notBefore = notBefore, notAfter = notAfter)
            assertEquals(notBefore.time / 1000, cert.notBefore.time / 1000)
            assertEquals(notAfter.time / 1000, cert.notAfter.time / 1000)
        } finally {
            Locale.setDefault(previous)
        }
    }
}
