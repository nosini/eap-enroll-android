package eu.appwerf.eapenroll

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.PopupMenu
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import java.math.BigInteger
import java.text.DateFormat
import java.util.Date
import java.util.concurrent.Executors

/**
 * The main screen: setup from a link while not enrolled, otherwise the
 * enrollment's status, what the user still needs to do, and details.
 */
class MainActivity : Activity() {
    private lateinit var prefs: SharedPreferences
    private lateinit var wifi: WifiManager
    private lateinit var enroller: Enroller
    private lateinit var deviceKeys: AndroidDeviceKeys

    private lateinit var scroll: ScrollView
    private lateinit var statusCard: LinearLayout
    private lateinit var statusHeader: View
    private lateinit var statusIcon: ImageView
    private lateinit var statusTitle: TextView
    private lateinit var statusText: TextView
    private lateinit var busyBar: View
    private lateinit var messageView: TextView
    private lateinit var statusActions: View
    private lateinit var checkButton: Button
    private lateinit var renewButton: Button
    private lateinit var tasks: LinearLayout
    private lateinit var setupCard: View
    private lateinit var setupTitle: TextView
    private lateinit var setupText: TextView
    private lateinit var setupField: EditText
    private lateinit var setupWpa3: Switch
    private lateinit var setupButton: Button
    private lateinit var pasteButton: Button
    private lateinit var detailsCard: View
    private lateinit var details: LinearLayout

    /** What the screen shows; read on the worker, rendered on the main thread. */
    private class Snapshot(val state: EnrollmentState?, val deviceKey: String?, val now: Long, val unreadable: Boolean = false)

    private var snapshot: Snapshot? = null
    private var approval: Int? = null
    private val screen = MainScreen
    private val onWorkFinished: () -> Unit = { refresh() }

    private val approvalListener = WifiManager.SuggestionUserApprovalStatusListener { status ->
        if (approval != status) AppLog.add("Suggestion approval: ${WifiSetup.approvalName(status)}")
        approval = status
        snapshot?.let(::render)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = getSharedPreferences(NetworkPrefs.PREFS, MODE_PRIVATE)
        wifi = getSystemService(WifiManager::class.java)
        enroller = Enrollment.enroller(this) { AppLog.add(it, toLogcat = false) }
        deviceKeys = AndroidDeviceKeys()
        setContentView(R.layout.activity_main)
        Ui.edgeToEdge(this, findViewById(R.id.root))
        bindViews()
        // The link isn't saved with the activity (it holds the one-time code);
        // kept in memory only while the activity is recreated.
        screen.setupText?.let { setupField.setText(it) }
        screen.setupText = null
        // Nothing to show until the state has been read, which may wait
        // for a request still running.
        statusCard.visibility = if (screen.busy) View.VISIBLE else View.GONE
        busyBar.visibility = if (screen.busy) View.VISIBLE else View.GONE
        if (screen.busy) showStatus(Tone.INFO, getString(R.string.status_working), null)
        messageView.visibility = View.GONE
        setupCard.visibility = View.GONE
        detailsCard.visibility = View.GONE
        screen.listener = onWorkFinished
        AppLog.addOnce(::deviceInfo)
        handleSetupIntent(intent)
    }

    private fun bindViews() {
        scroll = findViewById(R.id.scroll)
        statusCard = findViewById(R.id.status_card)
        statusHeader = findViewById(R.id.status_header)
        statusIcon = findViewById(R.id.status_icon)
        statusTitle = findViewById(R.id.status_title)
        statusText = findViewById(R.id.status_text)
        busyBar = findViewById(R.id.busy)
        messageView = findViewById(R.id.message)
        statusActions = findViewById(R.id.status_actions)
        checkButton = findViewById(R.id.check_now)
        renewButton = findViewById(R.id.renew_now)
        tasks = findViewById(R.id.tasks)
        setupCard = findViewById(R.id.setup_card)
        setupTitle = findViewById(R.id.setup_title)
        setupText = findViewById(R.id.setup_text)
        setupField = findViewById(R.id.setup_link)
        setupWpa3 = findViewById(R.id.setup_wpa3)
        setupButton = findViewById(R.id.set_up)
        pasteButton = findViewById(R.id.paste_link)
        detailsCard = findViewById(R.id.details_card)
        details = findViewById(R.id.details)

        findViewById<View>(R.id.menu_button).setOnClickListener(::showMenu)
        findViewById<View>(R.id.manual_link).setOnClickListener {
            startActivity(Intent(this, ManualSetupActivity::class.java))
        }
        pasteButton.setOnClickListener { pasteSetupLink() }
        setupButton.setOnClickListener { setUp() }
        checkButton.setOnClickListener { run(Action.CHECK) { Result.Of(enroller.maintain(byUser = true)) } }
        renewButton.setOnClickListener { renewWifiNow() }
        setupWpa3.setOnCheckedChangeListener { _, checked ->
            prefs.edit().putBoolean(NetworkPrefs.WPA3, checked).apply()
        }
        setupField.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) = updateButtons()
        })
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleSetupIntent(intent)
    }

    override fun onStart() {
        super.onStart()
        wifi.addSuggestionUserApprovalStatusListener(mainExecutor, approvalListener)
    }

    override fun onResume() {
        super.onResume()
        setupWpa3.isChecked = prefs.getBoolean(NetworkPrefs.WPA3, false)
        refresh()
    }

    override fun onStop() {
        wifi.removeSuggestionUserApprovalStatusListener(approvalListener)
        super.onStop()
    }

    override fun onDestroy() {
        if (screen.listener === onWorkFinished) screen.listener = null
        screen.setupText = if (isChangingConfigurations) setupField.text.toString() else null
        super.onDestroy()
    }

    // State and rendering

    /** Reads the state on the worker (it may wait for a running request) and renders it. */
    private fun refresh() {
        val app = applicationContext
        screen.execute {
            val snap = try {
                val state = enroller.state()
                if (state != null && state.problem == null) scheduleQuietly { Jobs.scheduleDaily(app) }
                val key = state?.let { runCatching { deviceKeys.describeWithAttestation(it.deviceAlias) }.getOrNull() }
                Snapshot(state, key, System.currentTimeMillis())
            } catch (e: Exception) {
                AppLog.add("Enrollment state unreadable: ${Errors.describe(e)}")
                Snapshot(null, null, System.currentTimeMillis(), unreadable = true)
            }
            runOnUiThread {
                if (isDestroyed) return@runOnUiThread
                snapshot = snap
                render(snap)
            }
        }
    }

    private fun render(snap: Snapshot) {
        val state = snap.state
        val busy = screen.busy
        val message = screen.message
        if (screen.setupUsed) {
            screen.setupUsed = false
            setupField.setText("")
        }
        val stopped = state?.problem == Problem.NEEDS_SETUP || state?.problem == Problem.DISABLED
        if (state == null || stopped) screen.setupRequested = false
        setupCard.visibility = if (state == null || stopped || screen.setupRequested) View.VISIBLE else View.GONE
        setupTitle.setText(if (state == null) R.string.setup_title else R.string.setup_again_title)

        statusCard.visibility = if (state != null || snap.unreadable || busy || message != null) View.VISIBLE else View.GONE
        detailsCard.visibility = if (state != null) View.VISIBLE else View.GONE
        statusActions.visibility = if (state != null && !stopped) View.VISIBLE else View.GONE
        if (state != null) {
            statusHeader.visibility = View.VISIBLE
            renderStatus(state, snap.now)
            renderDetails(state, snap.deviceKey)
        } else if (snap.unreadable && !busy) {
            statusHeader.visibility = View.VISIBLE
            showStatus(Tone.ERROR, getString(R.string.status_unreadable_title), Notifier.UNREADABLE)
        } else {
            // Not enrolled: the card only carries progress and the last result.
            statusHeader.visibility = if (busy) View.VISIBLE else View.GONE
            showStatus(Tone.INFO, getString(R.string.status_working), null)
        }
        renderTasks(state)
        busyBar.visibility = if (busy) View.VISIBLE else View.GONE
        messageView.visibility = if (message != null) View.VISIBLE else View.GONE
        messageView.text = message
        updateButtons()
    }

    private fun updateButtons() {
        val busy = screen.busy
        checkButton.isEnabled = !busy
        renewButton.isEnabled = !busy
        pasteButton.isEnabled = !busy
        setupButton.isEnabled = !busy && screen.pendingSetup == null && setupField.text.isNotBlank()
    }

    private enum class Tone { OK, INFO, WARNING, ERROR }

    private fun renderStatus(state: EnrollmentState, now: Long) {
        val attention = Notifier.attentionText(state, now)
        val wifiCert = state.wifiChain?.get(0)
        val time = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
        when {
            state.problem == Problem.NEEDS_SETUP || state.problem == Problem.DISABLED ->
                showStatus(Tone.ERROR, getString(R.string.status_stopped_title), attention)
            state.problem == Problem.USER_DISABLED ->
                showStatus(Tone.ERROR, getString(R.string.status_user_disabled_title), attention)
            attention != null -> showStatus(Tone.WARNING, getString(R.string.status_attention_title), attention)
            state.waitUntil > now -> showStatus(
                Tone.INFO, getString(R.string.status_wait_title),
                getString(R.string.status_wait_text, time.format(Date(state.waitUntil))),
            )
            wifiCert == null -> showStatus(
                Tone.WARNING, getString(R.string.status_no_wifi_title),
                listOfNotNull(getString(R.string.status_no_wifi_text), state.lastError).joinToString("\n\n"),
            )
            state.confirmPending && state.connectedAfterInstall ->
                showStatus(Tone.INFO, getString(R.string.status_confirming_title), getString(R.string.status_confirming_text))
            state.confirmPending -> showStatus(
                Tone.INFO, getString(R.string.status_unconfirmed_title),
                confirmHint() + " " + getString(R.string.confirm_explained),
            )
            else -> showStatus(
                Tone.OK, getString(R.string.status_ok_title),
                getString(R.string.status_ok_text, quotedSsid(state), dateOf(renewalStart(wifiCert))),
            )
        }
    }

    private fun showStatus(tone: Tone, title: String, text: String?) {
        statusTitle.text = title
        statusText.text = text
        statusText.visibility = if (text.isNullOrEmpty()) View.GONE else View.VISIBLE
        val (card, onCard, iconBg, icon) = when (tone) {
            Tone.OK -> listOf(R.color.surface, R.color.on_surface, R.color.primary, R.drawable.ic_check)
            Tone.INFO -> listOf(R.color.surface, R.color.on_surface, R.color.secondary_container, R.drawable.ic_schedule)
            Tone.WARNING -> listOf(R.color.warning_container, R.color.on_warning_container, R.color.on_warning_container, R.drawable.ic_warning)
            Tone.ERROR -> listOf(R.color.error_container, R.color.on_error_container, R.color.on_error_container, R.drawable.ic_error)
        }
        val iconTint = when (tone) {
            Tone.OK -> R.color.on_primary
            Tone.INFO -> R.color.on_secondary_container
            Tone.WARNING -> R.color.warning_container
            Tone.ERROR -> R.color.error_container
        }
        statusCard.backgroundTintList = ColorStateList.valueOf(getColor(card))
        statusTitle.setTextColor(getColor(onCard))
        statusText.setTextColor(getColor(onCard))
        statusIcon.setImageResource(icon)
        statusIcon.backgroundTintList = ColorStateList.valueOf(getColor(iconBg))
        statusIcon.imageTintList = ColorStateList.valueOf(getColor(iconTint))
    }

    private fun renderDetails(state: EnrollmentState, deviceKey: String?) {
        details.removeAllViews()
        val time = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
        state.profile?.let {
            val security = getString(
                if (prefs.getBoolean(NetworkPrefs.WPA3, false)) R.string.security_wpa3 else R.string.security_wpa2_wpa3,
            )
            detail(R.string.detail_network, "${quotedSsid(state)}\n$security")
        }
        val wifiCert = state.wifiChain?.get(0)
        detail(R.string.detail_username, Certs.commonName(wifiCert ?: state.deviceChain[0]))
        if (wifiCert != null) {
            val confirmed = getString(if (state.confirmPending) R.string.wifi_cert_unconfirmed else R.string.wifi_cert_confirmed)
            detail(
                R.string.detail_wifi_cert,
                getString(R.string.wifi_cert_value, dateOf(wifiCert.notAfter.time), dateOf(renewalStart(wifiCert))) +
                    "\n$confirmed",
            )
        }
        val device = state.deviceChain[0]
        detail(
            R.string.detail_device_cert,
            listOfNotNull(
                getString(R.string.device_cert_value, dateOf(device.notAfter.time)),
                deviceKey?.let { getString(R.string.device_key_value, it) },
            ).joinToString("\n"),
        )
        detail(R.string.detail_server, state.serverUrl)
        detail(
            R.string.detail_last_check,
            if (state.lastSuccessAt > 0) time.format(Date(state.lastSuccessAt)) else getString(R.string.never),
        )
        if (state.lastError != null && state.lastErrorAt > state.lastSuccessAt) {
            detail(R.string.detail_last_error, "${time.format(Date(state.lastErrorAt))}: ${state.lastError}")
        }
    }

    private fun detail(label: Int, value: String) {
        val row = LayoutInflater.from(this).inflate(R.layout.item_detail, details, false)
        row.findViewById<TextView>(R.id.detail_label).setText(label)
        row.findViewById<TextView>(R.id.detail_value).text = value
        details.addView(row)
    }

    private fun renderTasks(state: EnrollmentState?) {
        tasks.removeAllViews()
        if (state == null || state.problem != null) return
        if (approval == WifiManager.STATUS_SUGGESTION_APPROVAL_PENDING ||
            approval == WifiManager.STATUS_SUGGESTION_APPROVAL_REJECTED_BY_USER
        ) {
            task(TASK_APPROVE, R.string.task_approve_title, R.string.task_approve_text, R.string.task_approve_action, dismissable = false) {
                startActivity(Intent(Settings.Panel.ACTION_WIFI))
            }
        }
        if (!granted(Manifest.permission.ACCESS_FINE_LOCATION)) {
            task(TASK_LOCATION, R.string.task_location_title, R.string.task_location_text, R.string.task_location_action) {
                requestPermissions(
                    arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION),
                    REQUEST_LOCATION,
                )
            }
        } else if (!granted(Manifest.permission.ACCESS_BACKGROUND_LOCATION)) {
            // Android shows the "Allow all the time" choice in Settings.
            task(TASK_BACKGROUND, R.string.task_background_title, R.string.task_background_text, R.string.task_background_action) {
                requestPermissions(arrayOf(Manifest.permission.ACCESS_BACKGROUND_LOCATION), REQUEST_LOCATION)
            }
        }
        if (!localNetworkGranted()) {
            task(TASK_LOCAL_NETWORK, R.string.task_local_network_title, R.string.task_local_network_text, R.string.task_local_network_action) {
                requestPermissions(arrayOf(Manifest.permission.ACCESS_LOCAL_NETWORK), REQUEST_LOCAL_NETWORK)
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !granted(Manifest.permission.POST_NOTIFICATIONS)) {
            task(TASK_NOTIFICATIONS, R.string.task_notifications_title, R.string.task_notifications_text, R.string.task_notifications_action) {
                requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFICATIONS)
            }
        }
    }

    private fun task(id: String, title: Int, text: Int, action: Int, dismissable: Boolean = true, onAction: () -> Unit) {
        if (dismissable && id in dismissedTasks()) return
        val card = LayoutInflater.from(this).inflate(R.layout.item_task, tasks, false)
        card.findViewById<TextView>(R.id.task_title).setText(title)
        card.findViewById<TextView>(R.id.task_text).setText(text)
        card.findViewById<Button>(R.id.task_action).apply {
            setText(action)
            setOnClickListener { onAction() }
        }
        card.findViewById<Button>(R.id.task_dismiss).apply {
            visibility = if (dismissable) View.VISIBLE else View.GONE
            setOnClickListener {
                prefs.edit().putStringSet(PREF_DISMISSED, dismissedTasks() + id).apply()
                snapshot?.let(::render)
            }
        }
        tasks.addView(card)
    }

    private fun dismissedTasks(): Set<String> = prefs.getStringSet(PREF_DISMISSED, emptySet())!!.toSet()

    private fun confirmHint(): String = getString(
        when {
            !granted(Manifest.permission.ACCESS_FINE_LOCATION) -> R.string.confirm_hint_location
            !granted(Manifest.permission.ACCESS_BACKGROUND_LOCATION) -> R.string.confirm_hint_foreground
            else -> R.string.confirm_hint_background
        },
    )

    private fun granted(permission: String) = checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED

    private fun quotedSsid(state: EnrollmentState) = "“${state.profile?.ssid ?: "?"}”"

    private fun renewalStart(cert: java.security.cert.X509Certificate): Long {
        val start = cert.notBefore.time
        return start + (cert.notAfter.time - start) / 3 * 2
    }

    private fun dateOf(millis: Long): String = DateFormat.getDateInstance().format(Date(millis))

    // Menu

    private fun showMenu(anchor: View) {
        val state = snapshot?.state
        val popup = PopupMenu(this, anchor)
        val menu = popup.menu
        menu.add(0, MENU_WIFI, 0, R.string.menu_wifi_settings)
        if (state != null && state.problem != Problem.NEEDS_SETUP && state.problem != Problem.DISABLED) {
            menu.add(0, MENU_SET_UP_AGAIN, 1, R.string.menu_set_up_again)
        }
        menu.add(0, MENU_MANUAL, 2, R.string.menu_manual)
        menu.add(0, MENU_LOG, 3, R.string.menu_log)
        if (state != null || snapshot?.unreadable == true) menu.add(0, MENU_REMOVE, 4, R.string.menu_remove)
        popup.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                MENU_WIFI -> startActivity(Intent(Settings.Panel.ACTION_WIFI))
                MENU_SET_UP_AGAIN -> {
                    screen.setupRequested = true
                    snapshot?.let(::render)
                    scroll.post { scroll.smoothScrollTo(0, setupCard.top) }
                }
                MENU_MANUAL -> startActivity(Intent(this, ManualSetupActivity::class.java))
                MENU_LOG -> startActivity(Intent(this, LogActivity::class.java))
                MENU_REMOVE -> confirmRemove()
            }
            true
        }
        popup.show()
    }

    private fun confirmRemove() {
        AlertDialog.Builder(this)
            .setTitle(R.string.remove_title)
            .setMessage(R.string.remove_text)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.remove) { _, _ -> removeEnrollment() }
            .show()
    }

    // Actions

    private enum class Action { SETUP, CHECK, RENEW, REMOVE }

    private fun handleSetupIntent(intent: Intent?) {
        val data = intent?.data ?: return
        if (intent.action != Intent.ACTION_VIEW || data.scheme != "eapenroll") return
        // Reopened from recents: Android delivers the original link again,
        // whose code has most likely been used.
        if (intent.flags and Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY != 0) return
        // Clear it, so a recreated activity doesn't see the link again.
        intent.data = null
        try {
            val link = SetupUri.parse(data.toString())
            setupField.setText(data.toString())
            screen.setupRequested = true
            showMessage(getString(R.string.link_filled_in, link.serverUrl))
        } catch (e: Exception) {
            showMessage(getString(R.string.result_failed, Errors.describe(e)))
        }
    }

    private fun pasteSetupLink() {
        val text = Ui.clipboardText(this)
        if (text == null) {
            showMessage(getString(R.string.clipboard_empty))
            return
        }
        setupField.setText(text.trim())
    }

    private fun setUp() {
        val link = try {
            SetupUri.parse(setupField.text.toString().trim())
        } catch (e: Exception) {
            showMessage(getString(R.string.result_failed, Errors.describe(e)))
            return
        }
        if (screen.busy || screen.pendingSetup != null) return
        prefs.edit().putBoolean(NetworkPrefs.WPA3, setupWpa3.isChecked).apply()
        // Asked for before the first request: the app can't tell whether the
        // server is on the local network, and a blocked connection only times
        // out. Setup goes ahead whatever the answer.
        if (!localNetworkGranted()) {
            screen.pendingSetup = link
            updateButtons()
            requestPermissions(arrayOf(Manifest.permission.ACCESS_LOCAL_NETWORK), REQUEST_LOCAL_NETWORK)
            return
        }
        startSetup(link)
    }

    private fun startSetup(link: SetupUri) {
        val app = applicationContext
        run(Action.SETUP) {
            val before = runCatching { enroller.state()?.deviceAlias }.getOrNull()
            try {
                val outcome = enroller.setup(link)
                scheduleQuietly { Jobs.scheduleDaily(app) }
                Result.Of(outcome)
            } finally {
                // A new device credential was stored: the link is used up,
                // whatever happened after that. A setup that failed before
                // leaves the link in the field to be tried again.
                val after = runCatching { enroller.state()?.deviceAlias }.getOrNull()
                if (after != null && after != before) screen.markSetupUsed()
            }
        }
    }

    /** Asks for a new Wi-Fi certificate unless unconfirmed ones would pile up on the server. */
    private fun renewWifiNow() {
        run(Action.RENEW) {
            // Read on the worker: the enroller's lock may be held by a running request.
            val refusal = Enroller.manualWifiRenewalRefusal(enroller.state(), System.currentTimeMillis())
            if (refusal != null) {
                AppLog.add(refusal)
                return@run Result.Text(refusal)
            }
            Result.Of(enroller.maintain(renewWifi = true, byUser = true))
        }
    }

    /** What an action ended with: an outcome of the enroller, or text to show as it is. */
    private sealed interface Result {
        class Of(val outcome: Enroller.Outcome) : Result

        class Text(val text: String) : Result
    }

    /**
     * Runs [block] on the screen's worker, one action at a time, and shows
     * its result in whichever activity is there when it ends.
     */
    private fun run(action: Action, block: () -> Result) {
        if (!screen.start()) return
        snapshot?.let(::render) ?: updateButtons()
        val app = applicationContext
        val name = action.name.lowercase()
        AppLog.add("$name: started")
        screen.execute {
            val before = runCatching { enroller.state()?.wifiChain?.get(0)?.serialNumber }.getOrNull()
            val text = try {
                when (val result = block()) {
                    is Result.Text -> result.text
                    is Result.Of -> {
                        val after = enroller.state()
                        scheduleQuietly { Jobs.followUp(app, result.outcome, after) }
                        AppLog.add("$name: ${result.outcome}")
                        describe(action, result.outcome, after, before)
                    }
                }
            } catch (e: Exception) {
                AppLog.add("$name failed: ${Errors.describe(e)}")
                val advice = if (action == Action.SETUP) Enroller.setupLinkAdvice(e)?.let { "\n\n$it" } else null
                app.getString(R.string.result_failed, Errors.describe(e)) + advice.orEmpty()
            }
            try {
                Notifier.update(app)
            } finally {
                screen.finish(text)
            }
        }
    }

    private fun describe(action: Action, outcome: Enroller.Outcome, state: EnrollmentState?, before: BigInteger?): String {
        val error = state?.lastError?.let { "\n\n$it" } ?: ""
        val renewed = state?.wifiChain?.get(0)?.serialNumber.let { it != null && it != before }
        // A device credential renewal can fail after Wi-Fi was renewed all the same.
        val alsoRenewed = if (renewed && action != Action.SETUP) getString(R.string.result_renewed) + "\n\n" else ""
        return when (outcome) {
            Enroller.Outcome.OK -> when {
                action == Action.SETUP -> getString(R.string.result_set_up)
                renewed -> getString(R.string.result_renewed)
                else -> getString(R.string.result_up_to_date)
            }
            Enroller.Outcome.RETRY -> alsoRenewed + getString(R.string.result_retry) + error
            Enroller.Outcome.LATER -> alsoRenewed + getString(R.string.result_later) + error
            Enroller.Outcome.WAIT -> getString(
                R.string.result_wait,
                DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(state?.waitUntil ?: 0)),
            )
            Enroller.Outcome.STOPPED -> Notifier.attentionText(state, System.currentTimeMillis()) ?: outcome.name
            Enroller.Outcome.NOT_ENROLLED -> outcome.name
        }
    }

    private fun showMessage(text: String) {
        screen.message = text
        snapshot?.let(::render)
    }

    private fun removeEnrollment() {
        val app = applicationContext
        run(Action.REMOVE) {
            enroller.forget()
            Jobs.cancelAll(app)
            val status = wifi.removeNetworkSuggestions(emptyList())
            AppLog.add("Enrollment removed; suggestions removed: ${WifiSetup.statusName(status)}")
            Result.Text(app.getString(R.string.removed))
        }
    }

    /** A failure to schedule background work shouldn't hide what the request itself did. */
    private fun scheduleQuietly(block: () -> Unit) {
        try {
            block()
        } catch (e: Exception) {
            AppLog.add("Scheduling background work failed: ${Errors.describe(e)}")
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        AppLog.add("Permissions: " + permissions.indices.joinToString {
            "${permissions[it].substringAfterLast('.')}=" +
                if (grantResults.getOrNull(it) == PackageManager.PERMISSION_GRANTED) "granted" else "denied"
        })
        if (requestCode == REQUEST_LOCAL_NETWORK) {
            val link = screen.pendingSetup
            screen.pendingSetup = null
            // Empty when the request was interrupted before the user answered:
            // the user can tap "Set up" again.
            if (link != null && permissions.isNotEmpty()) startSetup(link)
        }
        refresh()
    }

    /** Android 17 blocks connections to the local network without this permission. */
    private fun localNetworkGranted() =
        Build.VERSION.SDK_INT < 37 || granted(Manifest.permission.ACCESS_LOCAL_NETWORK)

    private fun deviceInfo(): String {
        val strongBox = packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        return "Device: ${Build.MANUFACTURER} ${Build.MODEL}, Android ${Build.VERSION.RELEASE} " +
            "(API ${Build.VERSION.SDK_INT}), patch ${Build.VERSION.SECURITY_PATCH}, " +
            "StrongBox ${if (strongBox) "yes" else "no"}"
    }

    private companion object {
        const val REQUEST_LOCATION = 5
        const val REQUEST_NOTIFICATIONS = 6
        const val REQUEST_LOCAL_NETWORK = 7
        const val PREF_DISMISSED = "dismissed_tasks"
        const val TASK_APPROVE = "approve"
        const val TASK_LOCATION = "location"
        const val TASK_BACKGROUND = "background_location"
        const val TASK_NOTIFICATIONS = "notifications"
        const val TASK_LOCAL_NETWORK = "local_network"
        const val MENU_WIFI = 1
        const val MENU_SET_UP_AGAIN = 2
        const val MENU_MANUAL = 3
        const val MENU_LOG = 4
        const val MENU_REMOVE = 5
    }
}

/**
 * The main screen's work, and what the screen shows while its activity is
 * recreated (rotation, or leaving and coming back): work started from one
 * activity runs on a worker thread that outlives it, one action at a time,
 * and its result goes to the activity that is there when it ends. Fields
 * are for the main thread only.
 */
private object MainScreen {
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())

    /** An action is running. */
    var busy = false
        private set

    /** The last action's result. */
    var message: String? = null

    /** The user asked to set up again while enrolled (menu or a scanned link). */
    var setupRequested = false

    /** A setup waiting for the answer to the local network permission request. */
    var pendingSetup: SetupUri? = null

    /** The setup field's text while the activity is recreated. */
    var setupText: String? = null

    /** A setup used up the link in the field; the next render clears it. */
    var setupUsed = false

    /** The current activity, told when an action has ended. */
    var listener: (() -> Unit)? = null

    fun execute(block: () -> Unit) = worker.execute(block)

    /** Marks an action as running; false if one already is. */
    fun start(): Boolean {
        if (busy) return false
        busy = true
        message = null
        return true
    }

    /** From the worker: the setup's link has been used up. */
    fun markSetupUsed() = main.post {
        setupUsed = true
        setupRequested = false
        setupText = null
    }

    /** From the worker: the action has ended with [text]. */
    fun finish(text: String) = main.post {
        busy = false
        message = text
        listener?.invoke()
    }
}
