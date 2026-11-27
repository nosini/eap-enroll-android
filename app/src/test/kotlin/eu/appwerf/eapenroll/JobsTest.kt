package eu.appwerf.eapenroll

import eu.appwerf.eapenroll.Enroller.Outcome
import eu.appwerf.eapenroll.Jobs.FollowUp
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
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

    @Test
    fun aCheckInUseKeepsTheDailyJob() {
        val state = EnrollmentState(
            "https://enroll.example.org", "ab".repeat(32), "device-1",
            listOf(TestPki.leaf(TestPki.root("Test CA"), "alice")),
        )
        for (outcome in listOf(Outcome.OK, Outcome.RETRY, Outcome.WAIT, Outcome.LATER)) {
            assertTrue(outcome.name, Jobs.dailyNeeded(outcome, state))
            assertFalse(outcome.name, Jobs.dailyNeeded(outcome, state.copy(problem = Problem.USER_DISABLED)))
            // The check failed before the state could be read.
            assertFalse(outcome.name, Jobs.dailyNeeded(outcome, null))
        }
        // Nothing to do daily while stopped, or without an enrollment.
        assertFalse(Jobs.dailyNeeded(Outcome.STOPPED, state))
        assertFalse(Jobs.dailyNeeded(Outcome.NOT_ENROLLED, null))
    }

    @Test
    fun aDisabledAccountIsNotScheduledFor() {
        for (job in listOf(null, Jobs.DAILY, Jobs.SOON, Jobs.AFTER_WAIT)) {
            assertEquals(FollowUp.NONE, Jobs.followUpFor(Outcome.RETRY, job, Problem.USER_DISABLED))
            assertEquals(FollowUp.NONE, Jobs.followUpFor(Outcome.WAIT, job, Problem.USER_DISABLED))
        }
        // Other problems don't change what the outcome needs.
        assertEquals(FollowUp.SOON, Jobs.followUpFor(Outcome.RETRY, null, Problem.NEEDS_SETUP))
        assertEquals(FollowUp.AFTER_WAIT, Jobs.followUpFor(Outcome.WAIT, null, null))
    }
}
