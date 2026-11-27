package eu.appwerf.eapenroll

import eu.appwerf.eapenroll.Enroller.Outcome
import eu.appwerf.eapenroll.Jobs.FollowUp
import org.junit.Assert.assertEquals
import org.junit.Test

class JobsTest {
    @Test
    fun stoppedCancelsEverything() {
        for (job in listOf(null, Jobs.DAILY, Jobs.SOON, Jobs.AFTER_WAIT)) {
            assertEquals(FollowUp.CANCEL, Jobs.followUpFor(Outcome.STOPPED, job))
            assertEquals(FollowUp.CANCEL, Jobs.followUpFor(Outcome.NOT_ENROLLED, job))
            assertEquals(FollowUp.AFTER_WAIT, Jobs.followUpFor(Outcome.WAIT, job))
            assertEquals(FollowUp.NONE, Jobs.followUpFor(Outcome.OK, job))
            assertEquals(FollowUp.NONE, Jobs.followUpFor(Outcome.LATER, job))
        }
    }

    @Test
    fun retries() {
        assertEquals(FollowUp.SOON, Jobs.followUpFor(Outcome.RETRY, null))
        // The run after the server's wait has no backoff of its own.
        assertEquals(FollowUp.SOON, Jobs.followUpFor(Outcome.RETRY, Jobs.AFTER_WAIT))
        // Backoff, and the next day.
        assertEquals(FollowUp.NONE, Jobs.followUpFor(Outcome.RETRY, Jobs.SOON))
        assertEquals(FollowUp.NONE, Jobs.followUpFor(Outcome.RETRY, Jobs.DAILY))
    }
}
