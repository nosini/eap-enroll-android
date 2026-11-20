package eu.appwerf.eapenroll

import android.content.Context
import android.net.wifi.WifiManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import org.json.JSONObject

/**
 * Device credential keys in the Android Keystore: EC P-256, non-exportable,
 * in StrongBox if the phone has it (StrongBox usually lacks P-384).
 */
class AndroidDeviceKeys(private val log: (String) -> Unit = {}) : DeviceKeys {
    override fun create(): String {
        val alias = PREFIX + UUID.randomUUID()
        try {
            generate(alias, strongBox = true)
        } catch (e: StrongBoxUnavailableException) {
            generate(alias, strongBox = false)
        }
        log("Device key generated (${describe(alias)})")
        return alias
    }

    private fun generate(alias: String, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            // SHA-256 for the CSR; NONE because the TLS stack hashes itself
            // and signs the digest with NONEwithECDSA.
            .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(strongBox)
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).run {
            initialize(spec)
            generateKeyPair()
        }
    }

    override fun keyPair(alias: String): KeyPair {
        val entry = keyStore().getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("Device key $alias is missing")
        return KeyPair(entry.certificate.publicKey, entry.privateKey)
    }

    override fun delete(alias: String) {
        keyStore().deleteEntry(alias)
    }

    /** Deletes device keys that aren't in [keep], e.g. left over from an interrupted setup. */
    fun deleteOthers(keep: Set<String>) {
        val store = keyStore()
        store.aliases().toList().filter { it.startsWith(PREFIX) && it !in keep }.forEach { store.deleteEntry(it) }
    }

    /** Where the key lives: StrongBox, TEE or software. */
    fun describe(alias: String): String = try {
        val key = keyPair(alias).private
        val info = KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE).getKeySpec(key, KeyInfo::class.java)
        when (info.securityLevel) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox"
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
            KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software"
            else -> "security level ${info.securityLevel}"
        }
    } catch (e: Exception) {
        "unknown: ${e.message}"
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val PREFIX = "device-"
    }
}

/** Keeps the enrollment state as JSON in private preferences (backups are off). */
class PrefsStateStore(context: Context) : StateStore {
    private val prefs = context.getSharedPreferences("enrollment", Context.MODE_PRIVATE)

    override fun load(): EnrollmentState? =
        prefs.getString(KEY, null)?.let { EnrollmentState.fromJson(JSONObject(it)) }

    override fun save(state: EnrollmentState?) {
        val editor = prefs.edit()
        if (state == null) editor.remove(KEY) else editor.putString(KEY, state.toJson().toString())
        check(editor.commit()) { "Could not save the enrollment state" }
    }

    private companion object {
        const val KEY = "state"
    }
}

/**
 * Installs the Wi-Fi certificate as this app's network suggestion. Adding a
 * suggestion for the same SSID and security type replaces the previous one
 * and its key; other suggestions of this app are removed afterwards.
 */
class SuggestionInstaller(context: Context, private val log: (String) -> Unit = {}) : WifiInstaller {
    private val wifi = context.getSystemService(WifiManager::class.java)
    private val settings = context.getSharedPreferences(NetworkPrefs.PREFS, Context.MODE_PRIVATE)

    override fun install(profile: WifiProfile, identity: String, privateKey: PrivateKey, chain: List<X509Certificate>) {
        val network = NetworkSettings(
            ssid = profile.ssid,
            identity = identity,
            serverDomain = profile.serverDomain,
            wpa3 = settings.getBoolean(NetworkPrefs.WPA3, false),
            caCertificates = profile.serverCaCertificates,
        )
        val suggestion = WifiSetup.suggestion(network, privateKey, chain, notifyOnConnect = true)
        val status = wifi.addNetworkSuggestions(listOf(suggestion))
        check(status == WifiManager.STATUS_NETWORK_SUGGESTIONS_SUCCESS) {
            "addNetworkSuggestions: ${WifiSetup.statusName(status)}"
        }
        log("Network suggestion for '${profile.ssid}' installed " +
            "(${if (network.wpa3) "WPA3-Enterprise only" else "WPA2/WPA3-Enterprise"})")
        val stale = wifi.networkSuggestions.filter { it != suggestion }
        if (stale.isNotEmpty()) {
            val removed = wifi.removeNetworkSuggestions(stale)
            log("Removed ${stale.size} other suggestion(s): ${WifiSetup.statusName(removed)}")
        }
    }
}

/** Shared preference names of the network settings form. */
object NetworkPrefs {
    const val PREFS = "settings"
    const val WPA3 = "wpa3"
}

/** One place to build the enroller with its Android parts. */
object Enrollment {
    const val TAG = "EapEnroll"

    fun enroller(context: Context, log: (String) -> Unit = {}): Enroller {
        val app = context.applicationContext
        val both: (String) -> Unit = { Log.i(TAG, it); log(it) }
        return Enroller(AndroidDeviceKeys(both), SuggestionInstaller(app, both), PrefsStateStore(app), both)
    }
}
