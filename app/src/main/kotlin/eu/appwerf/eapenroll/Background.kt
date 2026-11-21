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
import android.util.Log
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
    private const val DAILY = 1
    private const val SOON = 2
    private const val AFTER_WAIT = 3

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

    /** What a check started by the user needs next: a retry soon, or a run after the server's wait. */
    fun followUp(context: Context, outcome: Enroller.Outcome, state: EnrollmentState?) {
        when (outcome) {
            Enroller.Outcome.RETRY -> runSoon(context)
            Enroller.Outcome.WAIT -> state?.let { runAt(context, it.waitUntil) }
            else -> {}
        }
    }

    fun cancelAll(context: Context) {
        context.getSystemService(JobScheduler::class.java).cancelAll()
    }

    /** Whether [params] is the one-off run, which retries with backoff. */
    fun isSoon(params: JobParameters) = params.jobId == SOON
}

class RenewJobService : JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        Thread {
            val enroller = Enrollment.enroller(this)
            val outcome = try {
                enroller.maintain()
            } catch (e: Exception) {
                Log.w(Enrollment.TAG, "Background renewal failed", e)
                Enroller.Outcome.RETRY
            }
            Log.i(Enrollment.TAG, "Background check: $outcome")
            if (outcome == Enroller.Outcome.WAIT) {
                try {
                    enroller.state()?.let { Jobs.runAt(this, it.waitUntil) }
                } catch (e: Exception) {
                    Log.w(Enrollment.TAG, "Scheduling the check after the wait failed", e)
                }
            }
            Notifier.update(this)
            jobFinished(params, outcome == Enroller.Outcome.RETRY && Jobs.isSoon(params))
        }.start()
        return true
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
        val at = System.currentTimeMillis()
        val suggestion = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(WifiManager.EXTRA_NETWORK_SUGGESTION, WifiNetworkSuggestion::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra(WifiManager.EXTRA_NETWORK_SUGGESTION)
        }
        val pending = goAsync()
        Thread {
            try {
                val enroller = Enrollment.enroller(context)
                val ssid = enroller.state()?.profile?.ssid
                Log.i(Enrollment.TAG, "Post-connection broadcast for '${suggestion?.ssid}'")
                // getSsid() returns the plain SSID; tolerate quotes all the same.
                val connected = suggestion?.ssid?.removeSurrounding("\"")
                if (ssid != null && connected == ssid && enroller.connectionObserved(at)) {
                    Jobs.runSoon(context, Jobs.AFTER_CONNECTION_DELAY_MS)
                }
            } catch (e: Exception) {
                Log.w(Enrollment.TAG, "Handling the connection broadcast failed", e)
            } finally {
                pending.finish()
            }
        }.start()
    }
}

/** A single notification for problems the user has to act on, or a certificate close to expiry. */
object Notifier {
    private const val CHANNEL = "renewal"
    private const val ID = 1

    fun update(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java)
        val text = attentionText(Enrollment.enroller(context).state(), System.currentTimeMillis())
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
            .build()
        // Without the notification permission (Android 13+) this is dropped silently.
        manager.notify(ID, notification)
    }

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
