package eu.appwerf.eapenroll

import android.app.Activity
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

/** The in-memory activity log, with a copy button for bug reports. */
class LogActivity : Activity() {
    private lateinit var text: TextView
    private lateinit var scroll: ScrollView
    private val listener: () -> Unit = { runOnUiThread { show() } }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_log)
        Ui.edgeToEdge(this, findViewById(R.id.root))
        Ui.backBar(this, R.string.log_title)
        text = findViewById(R.id.log_text)
        scroll = findViewById(R.id.scroll)
        findViewById<Button>(R.id.top_action).apply {
            visibility = View.VISIBLE
            setText(R.string.copy)
            setOnClickListener {
                Ui.copy(this@LogActivity, "log", AppLog.text())
                Toast.makeText(this@LogActivity, R.string.copied, Toast.LENGTH_SHORT).show()
            }
        }
    }

    override fun onStart() {
        super.onStart()
        AppLog.addListener(listener)
        show()
    }

    override fun onStop() {
        AppLog.removeListener(listener)
        super.onStop()
    }

    private fun show() {
        text.text = AppLog.text().ifEmpty { getString(R.string.log_empty) }
        scroll.post { scroll.fullScroll(View.FOCUS_DOWN) }
    }
}
