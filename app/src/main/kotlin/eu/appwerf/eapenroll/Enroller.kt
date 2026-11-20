package eu.appwerf.eapenroll

import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import org.json.JSONObject

/** Keys for the device credential: non-exportable, in the platform keystore on a phone. */
interface DeviceKeys {
    /** Generates a new EC key pair and returns its alias. */
    fun create(): String

    fun keyPair(alias: String): KeyPair

    fun delete(alias: String)
}

/** Hands a Wi-Fi key and certificate to the system, replacing the previous one. */
fun interface WifiInstaller {
    fun install(profile: WifiProfile, identity: String, privateKey: PrivateKey, chain: List<X509Certificate>)
}

interface StateStore {
    fun load(): EnrollmentState?

    fun save(state: EnrollmentState?)
}

enum class Problem {
    /** The server no longer accepts the device credential; a new setup link is needed. */
    NEEDS_SETUP,

    /** The administrator disabled the device or user. */
    DISABLED,
}

data class EnrollmentState(
    val serverUrl: String,
    val caFingerprint: String,
    val deviceAlias: String,
    val deviceChain: List<X509Certificate>,
    /** The device credential before the last renewal; deleted once the new one has been used. */
    val previousDeviceAlias: String? = null,
    val profile: WifiProfile? = null,
    /** The certificate in the current network suggestion, issuing CAs after it. */
    val wifiChain: List<X509Certificate>? = null,
    val wifiInstalledAt: Long = 0,
    /** The server hasn't been told yet that [wifiChain] works. */
    val confirmPending: Boolean = false,
    /** Wi-Fi connected through the suggestion after [wifiInstalledAt]. */
    val connectedAfterInstall: Boolean = false,
    val problem: Problem? = null,
    val lastError: String? = null,
    val lastErrorAt: Long = 0,
    val lastSuccessAt: Long = 0,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("server_url", serverUrl)
        put("ca_fingerprint", caFingerprint)
        put("device_alias", deviceAlias)
        put("device_chain", Pem.encodeChain(deviceChain))
        previousDeviceAlias?.let { put("previous_device_alias", it) }
        profile?.let { put("profile", Profiles.toJson(it)) }
        wifiChain?.let { put("wifi_chain", Pem.encodeChain(it)) }
        put("wifi_installed_at", wifiInstalledAt)
        put("confirm_pending", confirmPending)
        put("connected_after_install", connectedAfterInstall)
        problem?.let { put("problem", it.name) }
        lastError?.let { put("last_error", it) }
        put("last_error_at", lastErrorAt)
        put("last_success_at", lastSuccessAt)
    }

    companion object {
        fun fromJson(json: JSONObject) = EnrollmentState(
            serverUrl = json.getString("server_url"),
            caFingerprint = json.getString("ca_fingerprint"),
            deviceAlias = json.getString("device_alias"),
            deviceChain = Pem.certificates(json.getString("device_chain").toByteArray()),
            previousDeviceAlias = json.optStringOrNull("previous_device_alias"),
            profile = json.optJSONObject("profile")?.let { Profiles.fromJson(it) },
            wifiChain = json.optStringOrNull("wifi_chain")?.let { Pem.certificates(it.toByteArray()) },
            wifiInstalledAt = json.optLong("wifi_installed_at"),
            confirmPending = json.optBoolean("confirm_pending"),
            connectedAfterInstall = json.optBoolean("connected_after_install"),
            problem = json.optStringOrNull("problem")?.let { Problem.valueOf(it) },
            lastError = json.optStringOrNull("last_error"),
            lastErrorAt = json.optLong("last_error_at"),
            lastSuccessAt = json.optLong("last_success_at"),
        )

        private fun JSONObject.optStringOrNull(name: String): String? =
            if (has(name) && !isNull(name)) getString(name) else null
    }
}

/**
 * Enrollment and renewal against the enrollment server (the server's
 * docs/protocol.md): setup with a one-time code, Wi-Fi certificates with a
 * new key each time, device credential renewal, and confirming a new Wi-Fi
 * certificate once a connection proved that it works.
 *
 * All methods block on network I/O; call them off the main thread. One
 * lock per process serialises them, so the background job and the UI don't
 * interleave.
 */
class Enroller(
    private val keys: DeviceKeys,
    private val wifi: WifiInstaller,
    private val store: StateStore,
    private val log: (String) -> Unit = {},
    private val clock: () -> Long = System::currentTimeMillis,
) {
    enum class Outcome {
        NOT_ENROLLED,
        OK,

        /** A temporary failure; try again later. */
        RETRY,

        /** Needs the user: a new setup link, or the device was disabled. */
        STOPPED,
    }

    fun state(): EnrollmentState? = synchronized(LOCK) { store.load() }

    /**
     * Enrolls the device with the code from [link], then gets the first
     * Wi-Fi certificate. Throws if the device credential can't be obtained;
     * a failure after that is recorded in the state and retried by [maintain].
     */
    fun setup(link: SetupUri): Outcome = synchronized(LOCK) {
        log("Setting up with ${link.serverUrl}")
        val alias = keys.create()
        val chain = try {
            val keyPair = keys.keyPair(alias)
            val chain = EstClient(link.serverUrl, link.caFingerprint)
                .enrollDevice(link.code, Csr.create(keyPair, "eap-enroll"))
            checkIssued(chain, keyPair.public)
            chain
        } catch (e: Exception) {
            keys.delete(alias)
            throw e
        }
        val old = store.load()
        store.save(EnrollmentState(link.serverUrl, link.caFingerprint, alias, chain))
        old?.let {
            if (it.deviceAlias != alias) keys.delete(it.deviceAlias)
            it.previousDeviceAlias?.let(keys::delete)
        }
        log("Device credential for ${Certs.commonName(chain[0])}, valid until ${chain[0].notAfter}")
        maintainLocked(renewWifi = true)
    }

    /** Confirms, renews whatever is due, and retries what failed before. */
    fun maintain(renewWifi: Boolean = false): Outcome = synchronized(LOCK) { maintainLocked(renewWifi) }

    /**
     * Records that Wi-Fi connected through this app's suggestion at [at].
     * Returns true if that proves the current certificate works, so a
     * [maintain] run should confirm it.
     */
    fun connectionObserved(at: Long = clock()): Boolean = synchronized(LOCK) {
        val state = store.load() ?: return false
        if (!state.confirmPending || state.connectedAfterInstall) return state.confirmPending
        // A connection made before the new suggestion was installed could
        // still be reported just after it.
        if (at < state.wifiInstalledAt + INSTALL_SETTLE_MS) {
            log("Connection reported too soon after installing the certificate; not counted")
            return false
        }
        store.save(state.copy(connectedAfterInstall = true))
        log("Wi-Fi connected with the new certificate")
        true
    }

    /** Deletes the device keys and the stored state. Removing the suggestion is up to the caller. */
    fun forget() = synchronized(LOCK) {
        store.load()?.let {
            keys.delete(it.deviceAlias)
            it.previousDeviceAlias?.let(keys::delete)
        }
        store.save(null)
    }

    private fun maintainLocked(renewWifi: Boolean): Outcome {
        var state = store.load() ?: return Outcome.NOT_ENROLLED
        if (state.problem != null) return Outcome.STOPPED
        val now = clock()
        try {
            if (state.previousDeviceAlias != null) {
                state = retirePreviousCredential(state)
            }
            if (state.confirmPending && state.connectedAfterInstall) {
                state = confirmWifi(state)
            }
            if (Certs.renewalDue(state.deviceChain[0], now)) {
                state = renewDeviceCredential(state)
            }
            val wifiChain = state.wifiChain
            if (renewWifi || wifiChain == null || Certs.renewalDue(wifiChain[0], now)) {
                state = renewWifi(state)
            }
            store.save(state.copy(lastError = null, lastSuccessAt = clock()))
            return Outcome.OK
        } catch (e: EstException) {
            val problem = when (e.status) {
                401 -> Problem.NEEDS_SETUP
                403 -> Problem.DISABLED
                else -> null
            }
            fail(state, e, problem)
            return if (problem != null) Outcome.STOPPED else Outcome.RETRY
        } catch (e: IOException) {
            fail(state, e, null)
            return Outcome.RETRY
        } catch (e: GeneralSecurityException) {
            fail(state, e, null)
            return Outcome.RETRY
        } catch (e: IllegalArgumentException) {
            fail(state, e, null)
            return Outcome.RETRY
        } catch (e: IllegalStateException) {
            fail(state, e, null)
            return Outcome.RETRY
        }
    }

    private fun fail(state: EnrollmentState, e: Exception, problem: Problem?) {
        val message = Errors.describe(e)
        log("Enrollment request failed: $message")
        // The state may have advanced since [state] was read; keep that.
        val current = store.load() ?: state
        store.save(current.copy(problem = problem, lastError = message, lastErrorAt = clock()))
    }

    private fun client(state: EnrollmentState): EstClient {
        val keyPair = keys.keyPair(state.deviceAlias)
        return EstClient(state.serverUrl, state.caFingerprint, ClientCredential(keyPair.private, state.deviceChain))
    }

    /** Uses the new device credential once, which makes the server revoke the old one, then deletes the old key. */
    private fun retirePreviousCredential(state: EnrollmentState): EnrollmentState {
        val profile = client(state).wifiProfile() ?: state.profile
        state.previousDeviceAlias?.let(keys::delete)
        val next = state.copy(previousDeviceAlias = null, profile = profile)
        store.save(next)
        log("Previous device credential retired")
        return next
    }

    private fun confirmWifi(state: EnrollmentState): EnrollmentState {
        val leaf = state.wifiChain!![0]
        client(state).confirmWifi(leaf.serialNumber)
        val next = state.copy(confirmPending = false, connectedAfterInstall = false)
        store.save(next)
        log("Confirmed Wi-Fi certificate ${leaf.serialNumber.toString(16)}; older ones are revoked")
        return next
    }

    private fun renewDeviceCredential(state: EnrollmentState): EnrollmentState {
        log("Renewing the device credential")
        val alias = keys.create()
        val chain = try {
            val keyPair = keys.keyPair(alias)
            val identity = Certs.commonName(state.deviceChain[0]).ifEmpty { "eap-enroll" }
            val chain = client(state).reenrollDevice(Csr.create(keyPair, identity))
            checkIssued(chain, keyPair.public)
            chain
        } catch (e: Exception) {
            keys.delete(alias)
            throw e
        }
        state.previousDeviceAlias?.let(keys::delete)
        val next = state.copy(deviceAlias = alias, deviceChain = chain, previousDeviceAlias = state.deviceAlias)
        store.save(next)
        log("New device credential, valid until ${chain[0].notAfter}")
        return retirePreviousCredential(next)
    }

    private fun renewWifi(state: EnrollmentState): EnrollmentState {
        log("Requesting a Wi-Fi certificate")
        val client = client(state)
        val profile = client.wifiProfile() ?: state.profile
            ?: throw IOException("The server has no Wi-Fi profile")
        val keyPair = KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp384r1")) }
            .generateKeyPair()
        val identity = Certs.commonName(state.deviceChain[0])
        val chain = client.enrollWifi(Csr.create(keyPair, identity.ifEmpty { "eap-enroll" }))
        checkIssued(chain, keyPair.public)
        val wifiIdentity = Certs.commonName(chain[0])
        check(wifiIdentity.isNotEmpty()) { "The Wi-Fi certificate has no common name" }
        wifi.install(profile, wifiIdentity, keyPair.private, Certs.withoutRoots(chain))
        val next = state.copy(
            profile = profile,
            wifiChain = chain,
            wifiInstalledAt = clock(),
            confirmPending = true,
            connectedAfterInstall = false,
        )
        store.save(next)
        log("Wi-Fi certificate ${chain[0].serialNumber.toString(16)} for $wifiIdentity installed, " +
            "valid until ${chain[0].notAfter}")
        return next
    }

    private fun checkIssued(chain: List<X509Certificate>, publicKey: PublicKey) {
        val leaf = chain[0]
        check(leaf.publicKey.encoded.contentEquals(publicKey.encoded)) {
            "The server's certificate is not for this key"
        }
        check(leaf.basicConstraints == -1) { "The server returned a CA certificate" }
        chain.drop(1).forEach { check(it.basicConstraints >= 0) { "Not a CA certificate: ${it.subjectX500Principal}" } }
        if (chain.size > 1) leaf.verify(chain[1].publicKey)
    }

    companion object {
        private val LOCK = Any()

        /** Connections reported this soon after installing a certificate may predate it. */
        const val INSTALL_SETTLE_MS = 10_000L
    }
}

object Certs {
    /** The first CN of the subject, or "" if there is none. */
    fun commonName(cert: X509Certificate): String =
        cert.subjectX500Principal.getName(javax.security.auth.x500.X500Principal.RFC2253)
            .split(',')
            .map { it.trim() }
            .firstOrNull { it.startsWith("CN=") }
            ?.removePrefix("CN=") ?: ""

    /** Renew at 2/3 of the lifetime. */
    fun renewalDue(cert: X509Certificate, now: Long): Boolean {
        val start = cert.notBefore.time
        return now >= start + (cert.notAfter.time - start) / 3 * 2
    }

    /** Warn when less than a sixth of the lifetime is left (10 days of 60). */
    fun expiryWarning(cert: X509Certificate, now: Long): Boolean {
        val end = cert.notAfter.time
        return now >= end - (end - cert.notBefore.time) / 6
    }

    /** The chain without self-signed roots; Wi-Fi needs the client certificate and its intermediates. */
    fun withoutRoots(chain: List<X509Certificate>): List<X509Certificate> =
        listOf(chain[0]) + chain.drop(1).filter { it.subjectX500Principal != it.issuerX500Principal }
}

object Errors {
    /** A one-line description for the log and the status, with a hint for errors users can fix. */
    fun describe(e: Throwable): String {
        val text = "${e.javaClass.simpleName}: ${e.message}"
        // socket() fails with EPERM when the app may not use the network:
        // no INTERNET permission, or a "Network" permission toggled off.
        if (e is java.net.SocketException && e.message?.contains("EPERM") == true) {
            return "$text. The app isn't allowed to use the network; allow it in the app's permissions."
        }
        return text
    }
}
