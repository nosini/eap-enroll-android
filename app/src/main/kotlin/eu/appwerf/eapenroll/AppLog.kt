package eu.appwerf.eapenroll

import android.util.Log
import java.text.DateFormat
import java.util.Date

/**
 * The activity log shown in the app: the recent messages of this process,
 * kept in memory only. Everything also goes to logcat (tag EapEnroll).
 */
object AppLog {
    private const val TAG = "EapEnroll"
    private const val MAX_LINES = 500
    private val lines = ArrayDeque<String>()
    private val listeners = LinkedHashSet<() -> Unit>()
    private var started = false

    /** [toLogcat] is false for messages that were already logged elsewhere. */
    fun add(message: String, toLogcat: Boolean = true) {
        if (toLogcat) Log.i(TAG, message)
        val time = DateFormat.getTimeInstance(DateFormat.MEDIUM).format(Date())
        val copy = synchronized(this) {
            lines.addLast("$time $message")
            while (lines.size > MAX_LINES) lines.removeFirst()
            listeners.toList()
        }
        copy.forEach { it() }
    }

    /** Adds [message] only the first time it's called in this process. */
    fun addOnce(message: () -> String) {
        val first = synchronized(this) { !started.also { started = true } }
        if (first) add(message())
    }

    fun text(): String = synchronized(this) { lines.joinToString("\n") }

    /** [listener] runs on the thread that added the message. */
    fun addListener(listener: () -> Unit) = synchronized(this) { listeners += listener }

    fun removeListener(listener: () -> Unit) = synchronized(this) { listeners -= listener }
}
