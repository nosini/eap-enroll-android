package eu.appwerf.eapenroll

import android.Manifest
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.graphics.Typeface
import android.net.Uri
import android.net.wifi.WifiManager
import android.net.wifi.WifiNetworkSuggestion
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.InputType
import android.util.Log
import android.view.View
import android.view.WindowInsets
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.TextView
import java.io.File
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.text.DateFormat
import java.util.Date
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private lateinit var prefs: SharedPreferences
    private lateinit var vault: KeyVault
    private lateinit var wifi: WifiManager

    private lateinit var ssidField: EditText
    private lateinit var identityField: EditText
    private lateinit var domainField: EditText
    private lateinit var wpa3Button: RadioButton
    private lateinit var p256Button: RadioButton
    private lateinit var caSummary: TextView
    private lateinit var keySummary: TextView
    private lateinit var certSummary: TextView
    private lateinit var logView: TextView
    private lateinit var enrollSummary: TextView
    private lateinit var setupField: EditText
    private lateinit var enroller: Enroller
    private lateinit var deviceKeys: AndroidDeviceKeys
    private val worker: ExecutorService = Executors.newSingleThreadExecutor()

    private val caFile get() = File(filesDir, "ca.pem")
    private val csrFile get() = File(noBackupFilesDir, "csr.pem")
    private val chainFile get() = File(noBackupFilesDir, "chain.pem")

    private val approvalListener = WifiManager.SuggestionUserApprovalStatusListener { status ->
        log("Suggestion approval: ${WifiSetup.approvalName(status)}")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = getSharedPreferences(NetworkPrefs.PREFS, MODE_PRIVATE)
        vault = KeyVault(this)
        wifi = getSystemService(WifiManager::class.java)
        val uiLog: (String) -> Unit = { message -> runOnUiThread { appendLog(message) } }
        enroller = Enrollment.enroller(this, uiLog)
        deviceKeys = AndroidDeviceKeys()
        setContentView(buildUi())
        loadSettings()
        refreshSummaries()
        log(deviceInfo())
        handleSetupIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleSetupIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        refreshEnrollment()
    }

    override fun onDestroy() {
        worker.shutdown()
        super.onDestroy()
    }

    override fun onStart() {
        super.onStart()
        wifi.addSuggestionUserApprovalStatusListener(mainExecutor, approvalListener)
    }

    override fun onStop() {
        wifi.removeSuggestionUserApprovalStatusListener(approvalListener)
        super.onStop()
    }

    // UI

    private fun buildUi(): View {
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = dp(16)
            setPadding(pad, pad, pad, pad)
        }

        column.addView(heading("Enrollment"))
        enrollSummary = summary(column)
        setupField = field(column, "Setup link (eapenroll://setup?...)", InputType.TYPE_TEXT_VARIATION_URI).apply {
            // The link holds the one-time code: keep it out of the saved
            // instance state and the keyboard's learning.
            isSaveEnabled = false
            imeOptions = imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        }
        column.addView(button("Paste setup link") { pasteSetupLink() })
        column.addView(button("Set up with this link") { setUp() })
        column.addView(button("Check and renew now") { background("Checking") { enroller.maintain() } })
        column.addView(button("Get a new Wi-Fi certificate now") {
            background("Renewing") { enroller.maintain(renewWifi = true) }
        })
        column.addView(button("Allow location (lets the app confirm renewals)") { requestLocation() })
        column.addView(button("Allow notifications") { requestNotifications() })
        column.addView(button("Open Wi-Fi panel") { startActivity(Intent(Settings.Panel.ACTION_WIFI)) })
        column.addView(button("Remove enrollment") { removeEnrollment() })

        column.addView(heading("Manual setup (fallback)"))
        column.addView(heading("Network"))
        // Visible-password and URI variations keep keyboards from autocorrecting.
        ssidField = field(column, "SSID", InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)
        identityField = field(column, "EAP identity (username)", InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS)
        domainField = field(column, "RADIUS server domain", InputType.TYPE_TEXT_VARIATION_URI)
        val securityGroup = RadioGroup(this).apply { orientation = RadioGroup.HORIZONTAL }
        securityGroup.addView(RadioButton(this).apply {
            id = View.generateViewId(); text = "WPA2/WPA3-Enterprise"; isChecked = true
        })
        wpa3Button = RadioButton(this).apply { id = View.generateViewId(); text = "WPA3-Enterprise only" }
        securityGroup.addView(wpa3Button)
        column.addView(securityGroup)
        column.addView(button("Save settings") { attempt("Saving settings") { saveSettings(); log("Settings saved") } })
        column.addView(button("Import CA certificate (PEM)") { openDocument(REQUEST_CA) })
        caSummary = summary(column)

        column.addView(heading("Key and CSR"))
        val curveGroup = RadioGroup(this).apply { orientation = RadioGroup.HORIZONTAL }
        curveGroup.addView(RadioButton(this).apply {
            id = View.generateViewId(); text = "P-384"; isChecked = true
        })
        p256Button = RadioButton(this).apply { id = View.generateViewId(); text = "P-256" }
        curveGroup.addView(p256Button)
        column.addView(curveGroup)
        column.addView(button("Generate key and CSR") { generateKeyAndCsr() })
        column.addView(button("Share CSR") { shareCsr() })
        column.addView(button("Save CSR to file") { saveCsr() })
        column.addView(button("Copy CSR") { copyCsr() })
        keySummary = summary(column)

        column.addView(heading("Certificate"))
        column.addView(button("Import certificate file (PEM)") { openDocument(REQUEST_CERT) })
        column.addView(button("Paste certificate from clipboard") { pasteCertificate() })
        certSummary = summary(column)

        column.addView(heading("Wi-Fi"))
        column.addView(button("Add network suggestion") { addSuggestion() })
        column.addView(button("Save network through Settings") { saveThroughSettings() })
        column.addView(button("List this app's suggestions") { listSuggestions() })
        column.addView(button("Remove this app's suggestions") { removeSuggestions() })

        column.addView(heading("Clean-up"))
        column.addView(button("Delete stored key, CSR and certificate") { deleteKey() })

        column.addView(heading("Log"))
        logView = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 12f
            setTextIsSelectable(true)
        }
        column.addView(logView)
        column.addView(button("Copy log") { copyText("log", logView.text.toString()) })

        return ScrollView(this).apply {
            addView(column)
            setOnApplyWindowInsetsListener { view, insets ->
                val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime())
                view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
                WindowInsets.CONSUMED
            }
        }
    }

    private fun heading(text: String) = TextView(this).apply {
        this.text = text
        textSize = 20f
        setPadding(0, dp(16), 0, dp(4))
    }

    private fun field(parent: LinearLayout, hint: String, variation: Int) = EditText(this).apply {
        this.hint = hint
        inputType = InputType.TYPE_CLASS_TEXT or variation or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        isSingleLine = true
        parent.addView(this)
    }

    private fun summary(parent: LinearLayout) = TextView(this).apply {
        setTextIsSelectable(true)
        parent.addView(this)
    }

    private fun button(text: String, action: () -> Unit) = Button(this).apply {
        this.text = text
        isAllCaps = false
        setOnClickListener { action() }
    }

    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()

    private fun log(message: String) {
        Log.i(TAG, message)
        appendLog(message)
    }

    private fun appendLog(message: String) {
        val time = DateFormat.getTimeInstance(DateFormat.MEDIUM).format(Date())
        logView.append("$time $message\n")
    }

    private fun attempt(what: String, block: () -> Unit) {
        try {
            block()
        } catch (e: Exception) {
            Log.w(TAG, "$what failed", e)
            log("$what failed: ${e.javaClass.name}: ${e.message}")
        }
    }

    // Enrollment

    private fun handleSetupIntent(intent: Intent?) {
        val data = intent?.data ?: return
        if (intent.action != Intent.ACTION_VIEW || data.scheme != "eapenroll") return
        // Reopened from recents: Android delivers the original link again,
        // whose code has most likely been used.
        if (intent.flags and Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY != 0) return
        // Clear it, so a recreated activity doesn't see the link again.
        intent.data = null
        attempt("Reading setup link") {
            val link = SetupUri.parse(data.toString())
            setupField.setText(data.toString())
            log("Setup link for ${link.serverUrl} filled in. Tap \"Set up with this link\" to enroll.")
        }
    }

    private fun pasteSetupLink() = attempt("Pasting setup link") {
        val clip = getSystemService(ClipboardManager::class.java).primaryClip
        val text = clip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(this)?.toString()
        check(!text.isNullOrBlank()) { "Clipboard is empty" }
        setupField.setText(text.trim())
    }

    private fun setUp() = attempt("Setting up") {
        val link = SetupUri.parse(setupField.text.toString())
        background("Setting up") {
            val outcome = enroller.setup(link)
            scheduleQuietly { Jobs.scheduleDaily(this) }
            runOnUiThread { setupField.setText("") }
            outcome
        }
    }

    /** Runs [block] on the worker thread, logs its outcome and refreshes the status. */
    private fun background(what: String, block: () -> Enroller.Outcome) {
        saveSettingsQuietly()
        log("$what...")
        worker.execute {
            val message = try {
                val outcome = block()
                if (outcome == Enroller.Outcome.RETRY) scheduleQuietly { Jobs.runSoon(this) }
                "$what: $outcome"
            } catch (e: Exception) {
                Log.w(TAG, "$what failed", e)
                "$what failed: ${Errors.describe(e)}"
            }
            Notifier.update(this)
            runOnUiThread {
                log(message)
                refreshEnrollment()
            }
        }
    }

    /** A failure to schedule background work shouldn't hide what the request itself did. */
    private fun scheduleQuietly(block: () -> Unit) {
        try {
            block()
        } catch (e: Exception) {
            Log.w(TAG, "Scheduling background work failed", e)
            runOnUiThread { appendLog("Scheduling background work failed: ${Errors.describe(e)}") }
        }
    }

    private fun saveSettingsQuietly() {
        runCatching { saveSettings() }
    }

    private fun removeEnrollment() = attempt("Removing enrollment") {
        worker.execute {
            val message = try {
                enroller.forget()
                deviceKeys.deleteOthers(emptySet())
                Jobs.cancelAll(this)
                val status = wifi.removeNetworkSuggestions(emptyList())
                "Enrollment removed; suggestions removed: ${WifiSetup.statusName(status)}"
            } catch (e: Exception) {
                "Removing enrollment failed: ${e.javaClass.simpleName}: ${e.message}"
            }
            Notifier.update(this)
            runOnUiThread {
                log(message)
                refreshEnrollment()
            }
        }
    }

    private fun requestLocation() {
        val fine = checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        if (!fine) {
            requestPermissions(
                arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION),
                REQUEST_LOCATION,
            )
        } else {
            // Android shows the "Allow all the time" choice in Settings.
            requestPermissions(arrayOf(Manifest.permission.ACCESS_BACKGROUND_LOCATION), REQUEST_LOCATION)
        }
    }

    private fun requestNotifications() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFICATIONS)
        } else {
            log("Notifications need no permission on this Android version")
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        log("Permissions: " + permissions.indices.joinToString {
            "${permissions[it].substringAfterLast('.')}=" +
                if (grantResults.getOrNull(it) == PackageManager.PERMISSION_GRANTED) "granted" else "denied"
        })
        refreshEnrollment()
    }

    private fun refreshEnrollment() {
        worker.execute {
            val text = try {
                enrollmentText()
            } catch (e: Exception) {
                "Enrollment state unreadable: ${e.javaClass.simpleName}: ${e.message}"
            }
            runOnUiThread { enrollSummary.text = text }
        }
    }

    private fun enrollmentText(): String {
        val state = enroller.state()
        if (state != null && state.problem == null) scheduleQuietly { Jobs.scheduleDaily(this) }
        state ?: return "Not enrolled. Open the setup link from the enrollment server " +
            "(scan its QR code), or paste it below."
        val now = System.currentTimeMillis()
        val date = DateFormat.getDateInstance()
        val time = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
        val lines = ArrayList<String>()
        lines += "Server: ${state.serverUrl}"
        val device = state.deviceChain[0]
        lines += "Device credential: ${Certs.commonName(device)}, valid until ${date.format(device.notAfter)} " +
            "(key in ${deviceKeys.describe(state.deviceAlias)})"
        state.profile?.let {
            lines += "Network: '${it.ssid}', server ${it.serverDomain}, " +
                if (prefs.getBoolean(NetworkPrefs.WPA3, false)) "WPA3-Enterprise only" else "WPA2/WPA3-Enterprise"
        }
        val wifiCert = state.wifiChain?.get(0)
        if (wifiCert == null) {
            lines += "Wi-Fi certificate: none yet"
        } else {
            val start = wifiCert.notBefore.time
            val renewAt = Date(start + (wifiCert.notAfter.time - start) / 3 * 2)
            lines += "Wi-Fi certificate: serial ${wifiCert.serialNumber.toString(16)}, valid until " +
                "${date.format(wifiCert.notAfter)}, renewal from ${date.format(renewAt)}"
            lines += when {
                !state.confirmPending -> "Confirmed: older Wi-Fi certificates are revoked."
                state.connectedAfterInstall -> "Connected with it; confirming with the server."
                else -> "Not confirmed yet: " + confirmHint()
            }
        }
        when (state.problem) {
            Problem.NEEDS_SETUP -> lines += "PROBLEM: the server no longer accepts this phone; set it up with a new link."
            Problem.DISABLED -> lines += "PROBLEM: this phone is disabled on the server."
            null -> {}
        }
        state.lastError?.let { lines += "Last error (${time.format(Date(state.lastErrorAt))}): $it" }
        if (state.lastSuccessAt > 0) lines += "Last successful check: ${time.format(Date(state.lastSuccessAt))}"
        Notifier.attentionText(state, now)?.let { lines += "Attention: $it" }
        return lines.joinToString("\n")
    }

    private fun confirmHint(): String {
        val fine = checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        val background = checkSelfPermission(Manifest.permission.ACCESS_BACKGROUND_LOCATION) == PackageManager.PERMISSION_GRANTED
        return when {
            !fine -> "allow location, then turn Wi-Fi off and on while this app is open."
            !background -> "turn Wi-Fi off and on while this app is open (or allow location all the time)."
            else -> "happens on the next Wi-Fi connection."
        }
    }

    // Settings

    private fun loadSettings() {
        ssidField.setText(prefs.getString("ssid", ""))
        identityField.setText(prefs.getString("identity", ""))
        domainField.setText(prefs.getString("domain", ""))
        wpa3Button.isChecked = prefs.getBoolean(NetworkPrefs.WPA3, false)
        p256Button.isChecked = prefs.getString("curve", CURVE_P384) == CURVE_P256
    }

    /** Saves the form; throws if the domain isn't a valid host name, without saving anything. */
    private fun saveSettings() {
        val domainText = domainField.text.toString()
        val domain = if (domainText.isBlank()) "" else Input.normalizeDomain(domainText)
        domainField.setText(domain)
        prefs.edit()
            // Not trimmed: leading and trailing spaces are valid in an SSID.
            .putString("ssid", ssidField.text.toString())
            .putString("identity", identityField.text.toString().trim())
            .putString("domain", domain)
            .putBoolean(NetworkPrefs.WPA3, wpa3Button.isChecked)
            .putString("curve", if (p256Button.isChecked) CURVE_P256 else CURVE_P384)
            .apply()
    }

    private fun networkSettings(): NetworkSettings {
        saveSettings()
        check(caFile.exists()) { "No CA certificate imported" }
        return NetworkSettings(
            ssid = prefs.getString("ssid", "")!!,
            identity = prefs.getString("identity", "")!!,
            serverDomain = prefs.getString("domain", "")!!,
            wpa3 = prefs.getBoolean(NetworkPrefs.WPA3, false),
            caCertificates = Pem.certificates(caFile.readBytes()),
        )
    }

    private fun refreshSummaries() {
        caSummary.text = if (caFile.exists()) {
            runCatching { Pem.certificates(caFile.readBytes()).joinToString("\n") { describe(it) } }
                .getOrElse { "CA file unreadable: ${it.message}" }
        } else {
            "No CA certificate imported."
        }
        keySummary.text = if (vault.hasKey()) {
            "Key stored (encrypted). Public key SHA-256: ${fingerprint(vault.publicKeyEncoded()!!)}"
        } else {
            "No key stored."
        }
        certSummary.text = if (chainFile.exists()) {
            runCatching { Pem.certificates(chainFile.readBytes()).joinToString("\n") { describe(it) } }
                .getOrElse { "Certificate file unreadable: ${it.message}" }
        } else {
            "No certificate imported."
        }
    }

    // Key and CSR

    private fun generateKeyAndCsr() = attempt("Generating key") {
        saveSettings()
        val identity = prefs.getString("identity", "")!!
        check(identity.isNotEmpty()) { "Set the EAP identity first" }
        if (vault.hasKey()) {
            log("Replacing the stored key")
        }
        chainFile.delete()
        val curve = prefs.getString("curve", CURVE_P384)!!
        val keyPair = vault.generate(curve)
        val csr = Pem.encode("CERTIFICATE REQUEST", Csr.create(keyPair, identity))
        csrFile.writeText(csr)
        log("Generated $curve key; wrapping key in " +
            if (vault.lastWrapKeyInStrongBox == true) "StrongBox" else "TEE/software keystore")
        log("CSR for CN=$identity created")
        refreshSummaries()
    }

    private fun csrText(): String {
        check(csrFile.exists()) { "No CSR yet" }
        return csrFile.readText()
    }

    private fun shareCsr() = attempt("Sharing CSR") {
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "CSR")
            putExtra(Intent.EXTRA_TEXT, csrText())
        }
        startActivity(Intent.createChooser(intent, "Share CSR"))
    }

    private fun saveCsr() = attempt("Saving CSR") {
        csrText()
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/pkcs10"
            putExtra(Intent.EXTRA_TITLE, "wifi.csr")
        }
        @Suppress("DEPRECATION")
        startActivityForResult(intent, REQUEST_SAVE_CSR)
    }

    private fun copyCsr() = attempt("Copying CSR") { copyText("CSR", csrText()) }

    // Certificates

    private fun openDocument(requestCode: Int) {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        @Suppress("DEPRECATION")
        startActivityForResult(intent, requestCode)
    }

    @Deprecated("Platform Activity API; AndroidX is not used")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_ADD_NETWORKS) {
            val results = data?.getIntegerArrayListExtra(Settings.EXTRA_WIFI_NETWORK_RESULT_LIST)
            log("Settings add-network result: code $resultCode, per network $results " +
                "(0 = success, 1 = failed, 2 = already exists)")
            return
        }
        val uri = data?.data
        if (resultCode != RESULT_OK || uri == null) return
        when (requestCode) {
            REQUEST_CA -> attempt("Importing CA certificate") { importCa(readUri(uri)) }
            REQUEST_CERT -> attempt("Importing certificate") { importCertificate(readUri(uri)) }
            REQUEST_SAVE_CSR -> attempt("Saving CSR") {
                contentResolver.openOutputStream(uri)!!.use { it.write(csrText().toByteArray()) }
                log("CSR saved")
            }
        }
    }

    private fun readUri(uri: Uri): ByteArray {
        val bytes = contentResolver.openInputStream(uri)!!.use { it.readBytes() }
        check(bytes.size <= MAX_IMPORT_BYTES) { "File is too large" }
        return bytes
    }

    private fun importCa(data: ByteArray) {
        val certs = Pem.certificates(data)
        certs.forEach { check(it.basicConstraints >= 0) { "Not a CA certificate: ${it.subjectX500Principal}" } }
        caFile.writeText(certs.joinToString("") { Pem.encode("CERTIFICATE", it.encoded) })
        log("Imported ${certs.size} CA certificate(s)")
        refreshSummaries()
    }

    private fun pasteCertificate() = attempt("Pasting certificate") {
        val clip = getSystemService(ClipboardManager::class.java).primaryClip
        val text = clip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(this)?.toString()
        check(!text.isNullOrBlank()) { "Clipboard is empty" }
        importCertificate(text.toByteArray())
    }

    private fun importCertificate(data: ByteArray) {
        val publicKey = vault.publicKeyEncoded() ?: throw IllegalStateException("Generate a key first")
        val chain = Pem.certificates(data)
        val leaf = chain.first()
        check(leaf.publicKey.encoded.contentEquals(publicKey)) {
            "The first certificate doesn't belong to the stored key"
        }
        check(leaf.basicConstraints == -1) { "The first certificate is a CA certificate" }
        chain.drop(1).forEach {
            check(it.basicConstraints >= 0) { "Not a CA certificate: ${it.subjectX500Principal}" }
        }
        val identity = prefs.getString("identity", "")!!
        val cn = commonName(leaf)
        if (!cn.equals(identity, ignoreCase = true)) {
            log("Warning: certificate CN '$cn' differs from the EAP identity '$identity'")
        }
        runCatching { leaf.checkValidity() }.onFailure { log("Warning: certificate is not valid now: ${it.message}") }
        chainFile.writeText(chain.joinToString("") { Pem.encode("CERTIFICATE", it.encoded) })
        log("Imported certificate chain of ${chain.size}")
        refreshSummaries()
    }

    // Wi-Fi

    private fun buildSuggestion(): WifiNetworkSuggestion {
        check(chainFile.exists()) { "Import the signed certificate first" }
        val settings = networkSettings()
        val keyPair = vault.load()
        val chain = Pem.certificates(chainFile.readBytes())
        if (settings.ssid != settings.ssid.trim()) {
            log("Note: the SSID starts or ends with a space; it has to match the network exactly")
        }
        log("Network: SSID '${settings.ssid}' (${settings.ssid.length} characters), identity '${settings.identity}', " +
            "domain '${settings.serverDomain}', ${if (settings.wpa3) "WPA3-Enterprise only" else "WPA2/WPA3-Enterprise"}, " +
            "${settings.caCertificates.size} CA certificate(s), client chain of ${chain.size}")
        return WifiSetup.suggestion(settings, keyPair.private, chain)
    }

    private fun addSuggestion() = attempt("Adding suggestion") {
        val suggestion = buildSuggestion()
        val status = wifi.addNetworkSuggestions(listOf(suggestion))
        log("addNetworkSuggestions: ${WifiSetup.statusName(status)}")
        if (status == WifiManager.STATUS_NETWORK_SUGGESTIONS_SUCCESS) {
            log("Check the notification to allow the suggestion, then watch Wi-Fi settings. " +
                "Delete the stored key once the connection works.")
        }
    }

    private fun saveThroughSettings() = attempt("Saving through Settings") {
        val suggestion = buildSuggestion()
        val intent = Intent(Settings.ACTION_WIFI_ADD_NETWORKS).apply {
            putParcelableArrayListExtra(Settings.EXTRA_WIFI_NETWORK_LIST, arrayListOf(suggestion))
        }
        @Suppress("DEPRECATION")
        startActivityForResult(intent, REQUEST_ADD_NETWORKS)
    }

    private fun listSuggestions() = attempt("Listing suggestions") {
        val suggestions = wifi.networkSuggestions
        log("This app has ${suggestions.size} suggestion(s): " +
            suggestions.joinToString { it.ssid ?: "?" })
    }

    private fun removeSuggestions() = attempt("Removing suggestions") {
        val status = wifi.removeNetworkSuggestions(emptyList())
        log("removeNetworkSuggestions (all): ${WifiSetup.statusName(status)}")
    }

    private fun deleteKey() = attempt("Deleting key") {
        vault.delete()
        csrFile.delete()
        chainFile.delete()
        log("Stored key, CSR and certificate deleted")
        refreshSummaries()
    }

    // Helpers

    private fun copyText(label: String, text: String) {
        getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText(label, text))
        log("$label copied to clipboard")
    }

    private fun describe(cert: X509Certificate): String =
        "${cert.subjectX500Principal.name}\n  issuer ${cert.issuerX500Principal.name}\n" +
            "  valid until ${DateFormat.getDateInstance().format(cert.notAfter)}, " +
            "serial ${cert.serialNumber.toString(16)}"

    private fun commonName(cert: X509Certificate): String =
        cert.subjectX500Principal.name.split(',')
            .map { it.trim() }
            .firstOrNull { it.startsWith("CN=") }
            ?.removePrefix("CN=") ?: ""

    private fun fingerprint(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data)
            .joinToString("") { "%02x".format(it) }.take(32)

    private fun deviceInfo(): String {
        val strongBox = packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        return "Device: ${Build.MANUFACTURER} ${Build.MODEL}, Android ${Build.VERSION.RELEASE} " +
            "(API ${Build.VERSION.SDK_INT}), patch ${Build.VERSION.SECURITY_PATCH}, " +
            "StrongBox ${if (strongBox) "yes" else "no"}"
    }

    private companion object {
        const val TAG = "EapEnroll"
        const val CURVE_P384 = "secp384r1"
        const val CURVE_P256 = "secp256r1"
        const val REQUEST_CA = 1
        const val REQUEST_CERT = 2
        const val REQUEST_SAVE_CSR = 3
        const val REQUEST_ADD_NETWORKS = 4
        const val REQUEST_LOCATION = 5
        const val REQUEST_NOTIFICATIONS = 6
        const val MAX_IMPORT_BYTES = 64 * 1024
    }
}
