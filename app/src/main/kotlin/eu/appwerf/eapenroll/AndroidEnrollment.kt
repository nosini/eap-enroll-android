package eu.appwerf.eapenroll

import android.app.AppOpsManager
import android.content.Context
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Process
import android.os.SystemClock
import android.os.UserManager
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.UUID

/**
 * Device credential keys in the Android Keystore: EC P-256, non-exportable,
 * in StrongBox if the phone has it (StrongBox usually lacks P-384).
 *
 * With a challenge, the key gets a hardware key attestation, which the
 * server may require. Tried in this order: StrongBox with attestation, TEE
 * with attestation, then without attestation (StrongBox, TEE). Attestation
 * can fail for reasons that pass, e.g. while the phone has no remotely
 * provisioned attestation keys; a server that requires it then refuses the
 * request and the app retries later.
 */
class AndroidDeviceKeys(private val log: (String) -> Unit = {}) : DeviceKeys {
    override fun create(challenge: ByteArray?): String {
        val alias = PREFIX + UUID.randomUUID()
        val attempts = buildList {
            if (challenge != null) {
                add(true to challenge)
                add(false to challenge)
            }
            add(true to null)
            add(false to null)
        }
        var strongBoxAvailable = true
        var failure: Exception? = null
        for ((strongBox, attestationChallenge) in attempts) {
            if (strongBox && !strongBoxAvailable) continue
            val error: Exception = try {
                generate(alias, strongBox, attestationChallenge)
                val attested = attestation(alias)?.let { "attested, chain of ${it.size}" } ?: "not attested"
                log("Device key generated (${describe(alias)}, $attested)")
                return alias
            } catch (e: StrongBoxUnavailableException) {
                strongBoxAvailable = false
                runCatching { delete(alias) }
                continue
            } catch (e: GeneralSecurityException) {
                e
            } catch (e: ProviderException) {
                e
            }
            failure = error
            log("Generating the device key in ${if (strongBox) "StrongBox" else "the TEE"} " +
                "${if (attestationChallenge != null) "with" else "without"} attestation failed: ${Errors.describe(error)}")
            runCatching { delete(alias) }
        }
        throw failure ?: IllegalStateException("No way to generate the device key")
    }

    private fun generate(alias: String, strongBox: Boolean, challenge: ByteArray?) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            // SHA-256 for the CSR; NONE because the TLS stack hashes itself
            // and signs the digest with NONEwithECDSA.
            .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(strongBox)
            .apply { challenge?.let { setAttestationChallenge(it) } }
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).run {
            initialize(spec)
            generateKeyPair()
        }
    }

    override fun keyPair(alias: String): KeyPair {
        val entry = keyStore().getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: throw MissingDeviceKeyException(alias)
        return KeyPair(entry.certificate.publicKey, entry.privateKey)
    }

    /** A key generated without a challenge has only a self-signed certificate. */
    override fun attestation(alias: String): List<ByteArray>? =
        keyStore().getCertificateChain(alias)?.takeIf { it.size > 1 }?.map { it.encoded }

    override fun delete(alias: String) {
        keyStore().deleteEntry(alias)
    }

    override fun deleteOthers(keep: Set<String>) {
        val store = keyStore()
        store.aliases().toList().filter { it.startsWith(PREFIX) && it !in keep }.forEach { store.deleteEntry(it) }
    }

    /** Where the key lives (StrongBox, TEE or software), and whether it is attested. */
    fun describeWithAttestation(alias: String): String =
        describe(alias) + if (attestation(alias) != null) ", attested" else ", not attested"

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
    private val settings = context.getSharedPreferences(NetworkPrefs.PREFS, Context.MODE_PRIVATE)

    // A state stored without the security mode takes the one the network
    // settings had, which the app used for it.
    override fun load(): EnrollmentState? = prefs.getString(KEY, null)?.let {
        EnrollmentState.parse(it, wpa3 = settings.getBoolean(NetworkPrefs.WPA3, false))
    }

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
class SuggestionInstaller(private val context: Context, private val log: (String) -> Unit = {}) : WifiInstaller {
    private val wifi = context.getSystemService(WifiManager::class.java)

    /**
     * Wi-Fi refuses suggestions while the user disallows the app's Wi-Fi
     * control (the app op behind STATUS_NETWORK_SUGGESTIONS_ERROR_APP_DISALLOWED)
     * or, from Android 13, while an admin forbids adding networks.
     */
    override fun checkAllowed() {
        val appOps = context.getSystemService(AppOpsManager::class.java)
        val mode = appOps.unsafeCheckOpNoThrow(OP_CHANGE_WIFI_STATE, Process.myUid(), context.packageName)
        if (mode == AppOpsManager.MODE_IGNORED || mode == AppOpsManager.MODE_ERRORED) {
            throw WifiInstallException(WIFI_CONTROL_OFF)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            context.getSystemService(UserManager::class.java).hasUserRestriction(UserManager.DISALLOW_ADD_WIFI_CONFIG)
        ) {
            throw WifiInstallException(ADMIN_RESTRICTED)
        }
    }

    override fun install(profile: WifiProfile, wpa3: Boolean, identity: String, privateKey: PrivateKey, chain: List<X509Certificate>) {
        val network = NetworkSettings(
            ssid = profile.ssid,
            identity = identity,
            serverDomain = profile.serverDomain,
            wpa3 = wpa3,
            caCertificates = profile.serverCaCertificates,
        )
        val suggestion = WifiSetup.suggestion(network, privateKey, chain, notifyOnConnect = true)
        val status = wifi.addNetworkSuggestions(listOf(suggestion))
        when (status) {
            WifiManager.STATUS_NETWORK_SUGGESTIONS_SUCCESS -> {}
            WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_APP_DISALLOWED -> throw WifiInstallException(WIFI_CONTROL_OFF)
            WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_RESTRICTED_BY_ADMIN -> throw WifiInstallException(ADMIN_RESTRICTED)
            else -> throw WifiInstallException("Wi-Fi didn't take the network: ${WifiSetup.statusName(status)}")
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

private const val OP_CHANGE_WIFI_STATE = "android:change_wifi_state"
private const val WIFI_CONTROL_OFF = "The app may not change Wi-Fi networks. " +
    "Allow it under Settings > Apps > Special app access > Wi-Fi control, then tap \"Check now\"."
private const val ADMIN_RESTRICTED = "The device's administrator doesn't allow adding Wi-Fi networks."

/** Shared preference names of manual setup's network settings form. */
object NetworkPrefs {
    const val PREFS = "settings"
    const val WPA3 = "wpa3"
}

/** One place to build the enroller with its Android parts. */
object Enrollment {
    const val TAG = "EapEnroll"

    /**
     * [log] gets the enroller's messages; by default they also go to the
     * in-app activity log, which users can send in for bug reports.
     */
    fun enroller(
        context: Context,
        log: (String) -> Unit = { AppLog.add(it, toLogcat = false) },
    ): Enroller {
        val app = context.applicationContext
        // toLogcat is false above: both writes to logcat already.
        val both: (String) -> Unit = { Log.i(TAG, it); log(it) }
        return Enroller(
            AndroidDeviceKeys(both), SuggestionInstaller(app, both), PrefsStateStore(app), both,
            elapsedClock = SystemClock::elapsedRealtime,
            bootCount = { Settings.Global.getInt(app.contentResolver, Settings.Global.BOOT_COUNT, 0) },
        )
    }
}
