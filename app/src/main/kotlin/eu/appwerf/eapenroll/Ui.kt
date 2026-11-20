package eu.appwerf.eapenroll

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.view.View
import android.view.WindowInsets
import android.widget.TextView
import kotlin.math.max

object Ui {
    /** Draws behind the system bars and pads [root] by them and the keyboard. */
    fun edgeToEdge(activity: Activity, root: View) {
        // Android 15+ draws apps targeting it edge to edge anyway.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.VANILLA_ICE_CREAM) {
            @Suppress("DEPRECATION")
            activity.window.setDecorFitsSystemWindows(false)
        }
        root.setOnApplyWindowInsetsListener { view, insets ->
            val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
            val ime = insets.getInsets(WindowInsets.Type.ime())
            view.setPadding(bars.left, bars.top, bars.right, max(bars.bottom, ime.bottom))
            WindowInsets.CONSUMED
        }
    }

    /** A top bar with a back button and [title] (layout top_bar_back). */
    fun backBar(activity: Activity, title: Int) {
        activity.findViewById<View>(R.id.back_button).setOnClickListener { activity.finish() }
        activity.findViewById<TextView>(R.id.top_title).setText(title)
    }

    fun clipboardText(context: Context): String? {
        val clip = context.getSystemService(ClipboardManager::class.java).primaryClip
        return clip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(context)?.toString()
            ?.takeIf { it.isNotBlank() }
    }

    fun copy(context: Context, label: String, text: String) {
        context.getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText(label, text))
    }
}
