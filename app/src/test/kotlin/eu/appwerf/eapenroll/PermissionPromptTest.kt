package eu.appwerf.eapenroll

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** When a denied permission request sends the user to the app's settings. */
class PermissionPromptTest {
    @Test
    fun notOnAFirstRequest() {
        // Denied, cancelled with Back, or answered at once: Android may
        // still ask, so nothing points to the app's settings.
        assertFalse(openSettingsAfterDenial(requestedBefore = false, rationaleBefore = false, rationaleAfter = false))
        assertFalse(openSettingsAfterDenial(requestedBefore = false, rationaleBefore = true, rationaleAfter = false))
    }

    @Test
    fun notWhileAndroidWouldStillAsk() {
        assertFalse(openSettingsAfterDenial(requestedBefore = true, rationaleBefore = true, rationaleAfter = true))
    }

    @Test
    fun notWhenTheUserChoseDontAskAgain() {
        // Android showed a rationale before this request, so it was the
        // answer that stopped it from asking; the card still does something.
        assertFalse(openSettingsAfterDenial(requestedBefore = true, rationaleBefore = true, rationaleAfter = false))
    }

    @Test
    fun onceAndroidWontAskAnyMore() {
        assertTrue(openSettingsAfterDenial(requestedBefore = true, rationaleBefore = false, rationaleAfter = false))
    }
}
