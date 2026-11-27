package eu.appwerf.eapenroll

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.wifi.WifiManager
import android.net.wifi.WifiNetworkSuggestion
import android.os.Build
import android.os.PersistableBundle
import android.os.SystemClock
import android.provider.Settings
import java.text.DateFormat
import java.util.concurrent.TimeUnit

/**
 * Background work with the platform JobScheduler: a daily check that renews
 * what is due (and so retries daily), a one-off run as soon as a network is
 * available after a failed request, the same half a minute after Wi-Fi
 * connected with a new certificate, and a one-off run when a wait the server
 * asked for is over.
 */
object Jobs {
    const val DAILY = 1
    const val SOON = 2
    const val AFTER_WAIT = 3

    /** Records a connection through the app's suggestion, without network or waiting. */
    const val CONNECTION = 4

    const val EXTRA_SSID = "ssid"
    const val EXTRA_AT = "at"
    const val EXTRA_ELAPSED = "elapsed"
    const val EXTRA_BOOT = "boot"

    enum class FollowUp {
        NONE,

        /** The one-off run with backoff. */
        SOON,

        /** The one-off run once the server's wait is over. */
        AFTER_WAIT,

        /** Nothing until the user acts: every job is cancelled. */
        CANCEL,
    }

    /**
     * What a check that ended with [outcome] needs next. [jobId] is the job
     * that ran it, or null when the user started it, and [problem] the
     * state's problem after it. A failed SOON run retries through its own
     * backoff, and a failed daily run on the next day. A disabled account
     * is not scheduled for: the background checks stop, so a SOON or
     * AFTER_WAIT run would do nothing until the user asks again.
     */
    fun followUpFor(outcome: Enroller.Outcome, jobId: Int?, problem: Problem? = null): FollowUp = when (outcome) {
        Enroller.Outcome.STOPPED, Enroller.Outcome.NOT_ENROLLED -> FollowUp.CANCEL
        Enroller.Outcome.WAIT -> if (problem == Problem.USER_DISABLED) FollowUp.NONE else FollowUp.AFTER_WAIT
        Enroller.Outcome.RETRY -> when {
            problem == Problem.USER_DISABLED -> FollowUp.NONE
            jobId == null || jobId == AFTER_WAIT -> FollowUp.SOON
            else -> FollowUp.NONE
        }
        Enroller.Outcome.OK, Enroller.Outcome.LATER -> FollowUp.NONE
    }

    fun scheduleDaily(context: Context) {
        val scheduler = context.getSystemService(JobScheduler::class.java)
        if (scheduler.getPendingJob(DAILY) != null) return
        val job = JobInfo.Builder(DAILY, ComponentName(context, RenewJobService::class.java))
            .setPeriodic(TimeUnit.DAYS.toMillis(1), TimeUnit.HOURS.toMillis(6))
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
            .setPersisted(true)
            .build()
        scheduler.schedule(job)
    }

    /**
     * Wi-Fi has just connected: networks and VPNs are still switching over,
     * and a connection opened now can be cut in the middle of its TLS
     * handshake. Seen on a phone with an always-on VPN, where the
     * confirmation sent at once stalled until the server gave up.
     */
    const val AFTER_CONNECTION_DELAY_MS = 30_000L

    /** Runs the check once a network is available, not before [delayMs]. */
    fun runSoon(context: Context, delayMs: Long = 0) {
        val job = JobInfo.Builder(SOON, ComponentName(context, RenewJobService::class.java))
            .setMinimumLatency(delayMs)
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
            .setBackoffCriteria(TimeUnit.MINUTES.toMillis(30), JobInfo.BACKOFF_POLICY_EXPONENTIAL)
            .setPersisted(true)
            .build()
        context.getSystemService(JobScheduler::class.java).schedule(job)
    }

    /** Runs the check once [at] has passed (the server's Retry-After). */
    fun runAt(context: Context, at: Long) {
        // A second late, so the check doesn't find itself still waiting.
        val delay = (at - System.currentTimeMillis() + 1_000).coerceAtLeast(0)
        val job = JobInfo.Builder(AFTER_WAIT, ComponentName(context, RenewJobService::class.java))
            .setMinimumLatency(delay)
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
            .setPersisted(true)
            .build()
        context.getSystemService(JobScheduler::class.java).schedule(job)
    }

    /**
     * Hands a connection through the app's suggestion to a job, which reads
     * the enrollment itself. A broadcast may arrive while a check holds the
     * enroller's lock, and waiting for it there can time out. Scheduling
     * the same job ID again replaces one still pending.
     */
    fun connectionObserved(context: Context, ssid: String, at: Long, elapsed: Long, boot: Int) {
        val extras = PersistableBundle().apply {
            putString(EXTRA_SSID, ssid)
            putLong(EXTRA_AT, at)
            putLong(EXTRA_ELAPSED, elapsed)
            putInt(EXTRA_BOOT, boot)
        }
        val job = JobInfo.Builder(CONNECTION, ComponentName(context, RenewJobService::class.java))
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_NONE)
            .setExtras(extras)
            .build()
        context.getSystemService(JobScheduler::class.java).schedule(job)
    }

    /**
     * Whether a check that ended with [outcome] should make sure the daily
     * job is scheduled: there is an enrollment ([state], read after the
     * check), it is in use and has no problem. A check that failed before
     * the state could be read schedules nothing.
     */
    fun dailyNeeded(outcome: Enroller.Outcome, state: EnrollmentState?): Boolean =
        state != null && state.problem == null &&
            outcome != Enroller.Outcome.STOPPED && outcome != Enroller.Outcome.NOT_ENROLLED

    /** Schedules what a check needs next ([followUpFor]); [state] is the state after it. */
    fun followUp(context: Context, outcome: Enroller.Outcome, state: EnrollmentState?, jobId: Int? = null) {
        val problem = state?.problem
        // A check that got through schedules the daily job again, e.g. after
        // a disabled account was cleared while no activity was open to
        // refresh the screen.
        if (dailyNeeded(outcome, state)) scheduleDaily(context)
        when (followUpFor(outcome, jobId, problem)) {
            FollowUp.NONE -> {}
            FollowUp.SOON -> runSoon(context)
            FollowUp.AFTER_WAIT -> state?.let { runAt(context, it.waitUntil) }
            FollowUp.CANCEL -> cancelAll(context)
        }
    }

    fun cancelAll(context: Context) {
        context.getSystemService(JobScheduler::class.java).cancelAll()
    }
}

class RenewJobService : JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        if (params.jobId == Jobs.CONNECTION) {
            Thread {
                try {
                    recordConnection(params)
                } finally {
                    jobFinished(params, false)
                }
            }.start()
            return true
        }
        Thread {
            var outcome = Enroller.Outcome.RETRY
            var state: EnrollmentState? = null
            try {
                try {
                    val enroller = Enrollment.enroller(this)
                    outcome = enroller.maintain()
                    AppLog.add("Background check: $outcome")
                    state = runCatching { enroller.state() }.getOrNull()
                    Notifier.update(this)
                } catch (e: Exception) {
                    AppLog.add("Background renewal failed: ${Errors.describe(e)}")
                }
                // Before jobFinished(), which releases the wake lock: the
                // process may be frozen or killed right after it. Cancelling
                // all jobs here stops this one too, and a cancelled job isn't
                // rescheduled whatever onStopJob() answers.
                try {
                    Jobs.followUp(this, outcome, state, params.jobId)
                } catch (e: Exception) {
                    AppLog.add("Scheduling the next check failed: ${Errors.describe(e)}")
                }
            } finally {
                jobFinished(params, outcome == Enroller.Outcome.RETRY && params.jobId == Jobs.SOON)
            }
        }.start()
        return true
    }

    /**
     * Hands a connection the receiver passed on to the enroller, which
     * records it if it went through the stored profile's network and the
     * enrollment isn't stopped.
     */
    private fun recordConnection(params: JobParameters) {
        try {
            val ssid = params.extras.getString(Jobs.EXTRA_SSID) ?: return
            AppLog.add("Post-connection broadcast for '$ssid'")
            val connected = Enrollment.enroller(this).connectionObserved(
                ssid,
                params.extras.getLong(Jobs.EXTRA_AT),
                params.extras.getLong(Jobs.EXTRA_ELAPSED),
                params.extras.getInt(Jobs.EXTRA_BOOT),
            )
            if (connected) Jobs.runSoon(this, Jobs.AFTER_CONNECTION_DELAY_MS)
        } catch (e: Exception) {
            AppLog.add("Handling the connection broadcast failed: ${Errors.describe(e)}")
        }
    }

    override fun onStopJob(params: JobParameters): Boolean = true
}

/**
 * Wi-Fi connected through this app's suggestion. Sent only for suggestions
 * built with `setIsAppInteractionRequired(true)`, and only while the app may
 * read scan results (precise location, location on; in the background only
 * with "Allow all the time"). Not exported: only the system can send it.
 */
class ConnectionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != WifiManager.ACTION_WIFI_NETWORK_SUGGESTION_POST_CONNECTION) return
        val suggestion = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(WifiManager.EXTRA_NETWORK_SUGGESTION, WifiNetworkSuggestion::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra(WifiManager.EXTRA_NETWORK_SUGGESTION)
        }
        // getSsid() already unwraps the quotes of a configured SSID, so an
        // SSID that begins and ends with quotes keeps them.
        val ssid = suggestion?.ssid ?: return
        // Nothing here reads the enrollment: the enroller's lock may be held
        // by a request, and a receiver that waits can time out.
        val boot = Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT, 0)
        Jobs.connectionObserved(context, ssid, System.currentTimeMillis(), SystemClock.elapsedRealtime(), boot)
    }
}

/** A single notification for problems the user has to act on, or a certificate close to expiry. */
object Notifier {
    private const val CHANNEL = "renewal"
    private const val ID = 1

    /** Never throws: a failure to read the state or notify is only logged. */
    fun update(context: Context) {
        try {
            show(context)
        } catch (e: Exception) {
            AppLog.add("Updating the notification failed: ${Errors.describe(e)}")
        }
    }

    private fun show(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java)
        val text = try {
            attentionText(Enrollment.enroller(context).state(), System.currentTimeMillis())
        } catch (e: UnreadableStateException) {
            UNREADABLE
        }
        if (text == null) {
            manager.cancel(ID)
            return
        }
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL, context.getString(R.string.channel_renewal), NotificationManager.IMPORTANCE_DEFAULT),
        )
        val open = PendingIntent.getActivity(
            context, 0,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = Notification.Builder(context, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_enroll)
            .setContentTitle(context.getString(R.string.notification_title))
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(open)
            .setAutoCancel(true)
            .setOnlyAlertOnce(true)
            .build()
        // Without the notification permission (Android 13+) this is dropped silently.
        manager.notify(ID, notification)
    }

    const val UNREADABLE = "The app can't read its stored enrollment, so it can't renew the Wi-Fi certificate. " +
        "Set the phone up again with a new link."

    /** What needs the user's attention, or null. */
    fun attentionText(state: EnrollmentState?, now: Long): String? {
        if (state == null) return null
        when (state.problem) {
            Problem.NEEDS_SETUP -> {
                val device = state.deviceChain[0]
                if (now >= device.notAfter.time) {
                    return "The enrollment credential expired on ${DateFormat.getDateInstance().format(device.notAfter)}. " +
                        "Set the phone up again with a new link."
                }
                return "The enrollment server no longer accepts this phone. Set it up again with a new link."
            }
            Problem.DISABLED -> return "This phone was disabled on the enrollment server. Set it up again with a new link."
            Problem.USER_DISABLED -> return "Your account is disabled on the enrollment server. " +
                "Once it is enabled again, open the app and tap \"Check now\"."
            null -> {}
        }
        val date = DateFormat.getDateInstance()
        val wifi = state.wifiChain?.get(0)
        if (wifi != null && Certs.expiryWarning(wifi, now)) {
            return "The Wi-Fi certificate expires on ${date.format(wifi.notAfter)} and renewing it failed: ${state.lastError ?: "not tried yet"}"
        }
        val device = state.deviceChain[0]
        if (Certs.expiryWarning(device, now)) {
            return "The enrollment credential expires on ${date.format(device.notAfter)} and renewing it failed: ${state.lastError ?: "not tried yet"}"
        }
        return null
    }
}
