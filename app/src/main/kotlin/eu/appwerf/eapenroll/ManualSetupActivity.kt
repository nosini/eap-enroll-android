package eu.appwerf.eapenroll

import android.app.Activity
import android.app.AlertDialog
import android.content.ComponentName
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.net.wifi.WifiManager
import android.net.wifi.WifiNetworkSuggestion
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.EditText
import android.widget.RadioButton
import android.widget.Switch
import android.widget.TextView
import java.io.File
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.text.DateFormat

/**
 * Manual setup without an enrollment server: the app makes the key and a
 * CSR, the user has it signed and imports the certificate, and the app
 * hands key and certificate to Wi-Fi.
 */
class ManualSetupActivity : Activity() {
    private lateinit var prefs: SharedPreferences
    private lateinit var vault: KeyVault
    private lateinit var wifi: WifiManager

    private lateinit var ssidField: EditText
    private lateinit var identityField: EditText
    private lateinit var domainField: EditText
    private lateinit var wpa3Switch: Switch
    private lateinit var p256Button: RadioButton
    private lateinit var caSummary: TextView
    private lateinit var keySummary: TextView
    private lateinit var certSummary: TextView
    private lateinit var messageView: TextView

    private val caFile get() = File(filesDir, "ca.pem")
    private val csrFile get() = File(noBackupFilesDir, "csr.pem")
    private val chainFile get() = File(noBackupFilesDir, "chain.pem")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = getSharedPreferences(NetworkPrefs.PREFS, MODE_PRIVATE)
        vault = KeyVault(this)
        wifi = getSystemService(WifiManager::class.java)
        setContentView(R.layout.activity_manual)
        Ui.edgeToEdge(this, findViewById(R.id.root))
        Ui.backBar(this, R.string.manual_title)

        ssidField = findViewById(R.id.ssid)
        identityField = findViewById(R.id.identity)
        domainField = findViewById(R.id.domain)
        wpa3Switch = findViewById(R.id.wpa3)
        p256Button = findViewById(R.id.curve_p256)
        caSummary = findViewById(R.id.ca_summary)
        keySummary = findViewById(R.id.key_summary)
        certSummary = findViewById(R.id.cert_summary)
        messageView = findViewById(R.id.message)
        messageView.setOnClickListener { it.visibility = View.GONE }

        click(R.id.import_ca) { openDocument(REQUEST_CA) }
        click(R.id.generate) { generateKeyAndCsr() }
        click(R.id.share_csr) { shareCsr() }
        click(R.id.save_csr) { saveCsr() }
        click(R.id.copy_csr) { Ui.copy(this, "CSR", csrText()); show(getString(R.string.copied)) }
        click(R.id.import_cert) { openDocument(REQUEST_CERT) }
        click(R.id.paste_cert) {
            val text = Ui.clipboardText(this) ?: error(getString(R.string.clipboard_empty))
            check(text.length <= MAX_IMPORT_BYTES) { "The clipboard holds more than a certificate chain" }
            importCertificate(text.toByteArray())
        }
        click(R.id.add_suggestion) { addSuggestion() }
        click(R.id.save_settings_network) { saveThroughSettings() }
        click(R.id.list_suggestions) { listSuggestions() }
        click(R.id.remove_suggestions) { removeSuggestions() }
        click(R.id.delete_key) { deleteKey() }

        loadSettings()
        refreshSummaries()
    }

    override fun onPause() {
        // Keep what was typed; an invalid domain is reported when it's used.
        runCatching { saveSettings() }
        super.onPause()
    }

    private fun click(id: Int, action: () -> Unit) {
        findViewById<View>(id).setOnClickListener { attempt(action) }
    }

    /** Shows [message] in the bar at the bottom and logs it. */
    private fun show(message: String) {
        AppLog.add(message)
        messageView.text = message
        messageView.visibility = View.VISIBLE
    }

    private fun attempt(block: () -> Unit) {
        try {
            block()
        } catch (e: Exception) {
            show(getString(R.string.result_failed, Errors.describe(e)))
        }
    }

    // Settings

    private fun loadSettings() {
        ssidField.setText(prefs.getString("ssid", ""))
        identityField.setText(prefs.getString("identity", ""))
        domainField.setText(prefs.getString("domain", ""))
        wpa3Switch.isChecked = prefs.getBoolean(NetworkPrefs.WPA3, false)
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
            .putBoolean(NetworkPrefs.WPA3, wpa3Switch.isChecked)
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
            runCatching { Pem.certificates(caFile.readBytes()).joinToString("\n\n") { describe(it) } }
                .getOrElse { "CA file unreadable: ${it.message}" }
        } else {
            getString(R.string.no_ca)
        }
        // A stored key file that can't be read has no public key: say so
        // instead of failing here, so the user can still delete it.
        val publicKey = vault.publicKeyEncoded()
        keySummary.text = when {
            publicKey != null -> getString(R.string.key_stored, fingerprint(publicKey))
            vault.hasKey() -> getString(R.string.key_unreadable)
            else -> getString(R.string.no_key)
        }
        certSummary.text = if (chainFile.exists()) {
            runCatching { Pem.certificates(chainFile.readBytes()).joinToString("\n\n") { describe(it) } }
                .getOrElse { "Certificate file unreadable: ${it.message}" }
        } else {
            getString(R.string.no_certificate)
        }
    }

    // Key and CSR

    private fun generateKeyAndCsr() {
        saveSettings()
        val identity = prefs.getString("identity", "")!!
        check(identity.isNotEmpty()) { "Enter the username (EAP identity) first" }
        val replacing = vault.hasKey()
        val curve = prefs.getString("curve", CURVE_P384)!!
        // Replaces the stored key only once the new one is stored.
        val keyPair = vault.generate(curve)
        // The certificate was for the previous key.
        chainFile.delete()
        csrFile.writeText(Pem.encode("CERTIFICATE REQUEST", Csr.create(keyPair, identity)))
        val wrap = if (vault.lastWrapKeyInStrongBox == true) "StrongBox" else "TEE/software keystore"
        show(
            (if (replacing) "Replaced the stored key. " else "") +
                "Generated a $curve key (wrapped in $wrap) and a CSR for CN=$identity. Share it with the CA.",
        )
        refreshSummaries()
    }

    private fun csrText(): String {
        check(csrFile.exists()) { "No CSR yet" }
        return csrFile.readText()
    }

    private fun shareCsr() {
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "CSR")
            putExtra(Intent.EXTRA_TEXT, csrText())
        }
        startActivity(Intent.createChooser(intent, getString(R.string.share)))
    }

    private fun saveCsr() {
        csrText()
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/pkcs10"
            putExtra(Intent.EXTRA_TITLE, "wifi.csr")
        }
        @Suppress("DEPRECATION")
        startActivityForResult(intent, REQUEST_SAVE_CSR)
    }

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
            show("Settings add-network result: code $resultCode, per network $results " +
                "(0 = success, 1 = failed, 2 = already exists)")
            return
        }
        val uri = data?.data
        if (resultCode != RESULT_OK || uri == null) return
        when (requestCode) {
            REQUEST_CA -> attempt { importCa(readUri(uri)) }
            REQUEST_CERT -> attempt { importCertificate(readUri(uri)) }
            REQUEST_SAVE_CSR -> attempt {
                contentResolver.openOutputStream(uri)!!.use { it.write(csrText().toByteArray()) }
                show("CSR saved")
            }
        }
    }

    /** Stops reading past [MAX_IMPORT_BYTES]: the picker offers any file, however large. */
    private fun readUri(uri: Uri): ByteArray =
        contentResolver.openInputStream(uri)!!.use { Streams.readLimited(it, MAX_IMPORT_BYTES, "The file") }

    private fun importCa(data: ByteArray) {
        val certs = Pem.certificates(data)
        certs.forEach { check(it.basicConstraints >= 0) { "Not a CA certificate: ${it.subjectX500Principal}" } }
        caFile.writeText(certs.joinToString("") { Pem.encode("CERTIFICATE", it.encoded) })
        show("Imported ${certs.size} CA certificate(s)")
        refreshSummaries()
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
        Certs.checkChain(chain)
        val warnings = ArrayList<String>()
        val identity = prefs.getString("identity", "")!!
        val cn = Certs.commonName(leaf)
        if (!cn.equals(identity, ignoreCase = true)) {
            warnings += "Its CN '$cn' differs from the username '$identity'."
        }
        runCatching { leaf.checkValidity() }.onFailure { warnings += "It isn't valid now: ${it.message}" }
        chainFile.writeText(chain.joinToString("") { Pem.encode("CERTIFICATE", it.encoded) })
        show((listOf("Imported a certificate chain of ${chain.size}.") + warnings).joinToString(" "))
        refreshSummaries()
    }

    // Wi-Fi

    private fun buildSuggestion(): WifiNetworkSuggestion {
        check(chainFile.exists()) { "Import the signed certificate first" }
        val settings = networkSettings()
        val keyPair = vault.load()
        // Wi-Fi takes at most five certificates; the root isn't needed.
        val chain = Certs.withoutRoots(Pem.certificates(chainFile.readBytes()))
        AppLog.add("Network: SSID '${settings.ssid}' (${settings.ssid.length} characters), identity '${settings.identity}', " +
            "domain '${settings.serverDomain}', ${if (settings.wpa3) "WPA3-Enterprise only" else "WPA2/WPA3-Enterprise"}, " +
            "${settings.caCertificates.size} CA certificate(s), client chain of ${chain.size}")
        return WifiSetup.suggestion(settings, keyPair.private, chain)
    }

    private fun addSuggestion() {
        val suggestion = buildSuggestion()
        val status = wifi.addNetworkSuggestions(listOf(suggestion))
        if (status == WifiManager.STATUS_NETWORK_SUGGESTIONS_SUCCESS) {
            val spaces = with(prefs.getString("ssid", "")!!) { this != trim() }
            show("Network added. Allow it if Android asks, then check Wi-Fi settings." +
                if (spaces) " The SSID starts or ends with a space; it has to match the network exactly." else "")
        } else {
            show("Adding the network failed: ${WifiSetup.statusName(status)}")
        }
    }

    /**
     * Hands the network to Settings. The suggestion carries the private key
     * in the clear, and any app can claim this action, so it goes only to a
     * system app, named explicitly.
     */
    private fun saveThroughSettings() {
        val action = Intent(Settings.ACTION_WIFI_ADD_NETWORKS)
        val handler = systemActivityFor(action)
            ?: throw IllegalStateException("No system app on this phone adds Wi-Fi networks this way")
        val suggestion = buildSuggestion()
        val intent = action.apply {
            component = handler
            putParcelableArrayListExtra(Settings.EXTRA_WIFI_NETWORK_LIST, arrayListOf(suggestion))
        }
        @Suppress("DEPRECATION")
        startActivityForResult(intent, REQUEST_ADD_NETWORKS)
    }

    /** The system activity for [intent], Settings if there are several. */
    private fun systemActivityFor(intent: Intent): ComponentName? {
        val flags = (PackageManager.MATCH_SYSTEM_ONLY or PackageManager.MATCH_DEFAULT_ONLY).toLong()
        val handlers = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(flags))
        } else {
            @Suppress("DEPRECATION")
            packageManager.queryIntentActivities(intent, flags.toInt())
        }.map { it.activityInfo }
            .filter { it.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0 }
        val chosen = handlers.firstOrNull { it.packageName == SETTINGS_PACKAGE } ?: handlers.firstOrNull()
        return chosen?.let { ComponentName(it.packageName, it.name) }
    }

    private fun listSuggestions() {
        val suggestions = wifi.networkSuggestions
        show("This app has ${suggestions.size} network(s)" +
            if (suggestions.isEmpty()) "." else ": " + suggestions.joinToString { "'${it.ssid ?: "?"}'" })
    }

    private fun removeSuggestions() {
        // state() may wait for a request that holds the enroller's lock.
        Thread {
            val enrolled = runCatching { Enrollment.enroller(this).state() != null }.getOrDefault(false)
            runOnUiThread { confirmRemoveSuggestions(enrolled) }
        }.start()
    }

    private fun confirmRemoveSuggestions(enrolled: Boolean) {
        AlertDialog.Builder(this)
            .setTitle(R.string.remove_networks_title)
            .setMessage(if (enrolled) R.string.remove_networks_enrolled_text else R.string.remove_networks_text)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.remove) { _, _ ->
                val status = wifi.removeNetworkSuggestions(emptyList())
                show("Removed this app's networks: ${WifiSetup.statusName(status)}")
            }
            .show()
    }

    private fun deleteKey() {
        vault.delete()
        csrFile.delete()
        chainFile.delete()
        show("Stored key, CSR and certificate deleted")
        refreshSummaries()
    }

    // Helpers

    private fun describe(cert: X509Certificate): String =
        "${cert.subjectX500Principal.name}\nIssuer: ${cert.issuerX500Principal.name}\n" +
            "Valid until ${DateFormat.getDateInstance().format(cert.notAfter)}, " +
            "serial ${cert.serialNumber.toString(16)}"

    private fun fingerprint(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data)
            .joinToString("") { "%02x".format(it) }.take(32)

    private companion object {
        const val CURVE_P384 = "secp384r1"
        const val CURVE_P256 = "secp256r1"
        const val REQUEST_CA = 1
        const val REQUEST_CERT = 2
        const val REQUEST_SAVE_CSR = 3
        const val REQUEST_ADD_NETWORKS = 4
        const val MAX_IMPORT_BYTES = 64 * 1024
        const val SETTINGS_PACKAGE = "com.android.settings"
    }
}
