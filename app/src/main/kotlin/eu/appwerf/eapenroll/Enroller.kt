package eu.appwerf.eapenroll

import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.ProviderException
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import org.json.JSONObject

/** Keys for the device credential: non-exportable, in the platform keystore on a phone. */
interface DeviceKeys {
    /**
     * Generates a new EC key pair and returns its alias. With [challenge],
     * the key gets a hardware key attestation for that challenge if the
     * phone can make one; otherwise it is generated without.
     */
    fun create(challenge: ByteArray? = null): String

    /** Throws [MissingDeviceKeyException] if there is no key [alias]. */
    fun keyPair(alias: String): KeyPair

    /** The key's attestation chain (DER, leaf first), or null if it has none. */
    fun attestation(alias: String): List<ByteArray>?

    fun delete(alias: String)

    /** Deletes the device keys not in [keep], e.g. left over from an interrupted setup or renewal. */
    fun deleteOthers(keep: Set<String>)
}

/**
 * Hands a Wi-Fi key and certificate to the system, replacing the previous
 * one. Throws [WifiInstallException] if the system won't take it.
 */
fun interface WifiInstaller {
    /** [wpa3]: WPA3-Enterprise only, otherwise WPA2/WPA3-Enterprise. */
    fun install(profile: WifiProfile, wpa3: Boolean, identity: String, privateKey: PrivateKey, chain: List<X509Certificate>)

    /** Throws [WifiInstallException] if [install] can't work now, e.g. while the user disallows Wi-Fi control. */
    fun checkAllowed() {}

    /** Whether the app's network suggestion for [profile] is currently installed in Wi-Fi. */
    fun isInstalled(profile: WifiProfile): Boolean = true
}

/**
 * The phone didn't take a Wi-Fi certificate, or won't now. The server has
 * issued one when [install] fails, and every new one stays valid until it
 * expires or a newer one is confirmed, so it isn't retried soon.
 */
class WifiInstallException(message: String, cause: Throwable? = null) : Exception(message, cause)

interface StateStore {
    /** Throws [UnreadableStateException] if a stored state can't be read. */
    fun load(): EnrollmentState?

    fun save(state: EnrollmentState?)
}

enum class Problem {
    /** The server no longer accepts the device credential; a new setup link is needed. */
    NEEDS_SETUP,

    /**
     * The administrator disabled the device, or the server saw a replaced
     * device credential used again and disabled the device. Needs a new
     * setup link.
     */
    DISABLED,

    /** The user's account is disabled. Retried only when the user asks, since it can be enabled again. */
    USER_DISABLED,
}

data class EnrollmentState(
    val serverUrl: String,
    val caFingerprint: String,
    val deviceAlias: String,
    val deviceChain: List<X509Certificate>,
    /** The device credential before the last renewal; deleted once the new one has been used. */
    val previousDeviceAlias: String? = null,
    val profile: WifiProfile? = null,
    /** The network is WPA3-Enterprise only; chosen at setup. */
    val wpa3: Boolean = false,
    /** The certificate in the current network suggestion, issuing CAs after it. */
    val wifiChain: List<X509Certificate>? = null,
    val wifiInstalledAt: Long = 0,
    /**
     * [wifiInstalledAt] on the monotonic clock, to tell connections from
     * before the install apart within a boot; 0 for a state stored before
     * it was kept.
     */
    val wifiInstalledElapsed: Long = 0,
    /** The boot [wifiInstalledElapsed] belongs to; 0 when unknown. */
    val wifiInstalledBoot: Int = 0,
    /** The server hasn't been told yet that [wifiChain] works. */
    val confirmPending: Boolean = false,
    /** Wi-Fi connected through the suggestion after [wifiInstalledAt]. */
    val connectedAfterInstall: Boolean = false,
    val problem: Problem? = null,
    /** The server asked (429 with Retry-After) for no requests before this time. */
    val waitUntil: Long = 0,
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
        put("wpa3", wpa3)
        wifiChain?.let { put("wifi_chain", Pem.encodeChain(it)) }
        put("wifi_installed_at", wifiInstalledAt)
        put("wifi_installed_elapsed", wifiInstalledElapsed)
        put("wifi_installed_boot", wifiInstalledBoot)
        put("confirm_pending", confirmPending)
        put("connected_after_install", connectedAfterInstall)
        problem?.let { put("problem", it.name) }
        put("wait_until", waitUntil)
        lastError?.let { put("last_error", it) }
        put("last_error_at", lastErrorAt)
        put("last_success_at", lastSuccessAt)
    }

    companion object {
        /**
         * Reads a stored state; throws [UnreadableStateException] if it
         * can't. [wpa3] is used for a state stored without it.
         */
        fun parse(json: String, wpa3: Boolean = false): EnrollmentState = try {
            fromJson(JSONObject(json), wpa3)
        } catch (e: Exception) {
            throw UnreadableStateException(e)
        }

        fun fromJson(json: JSONObject, wpa3: Boolean = false) = EnrollmentState(
            serverUrl = json.getString("server_url"),
            caFingerprint = json.getString("ca_fingerprint"),
            deviceAlias = json.getString("device_alias"),
            deviceChain = Pem.certificates(json.getString("device_chain").toByteArray()),
            previousDeviceAlias = json.optStringOrNull("previous_device_alias"),
            profile = json.optJSONObject("profile")?.let { Profiles.fromJson(it) },
            wpa3 = json.optBoolean("wpa3", wpa3),
            wifiChain = json.optStringOrNull("wifi_chain")?.let { Pem.certificates(it.toByteArray()) },
            wifiInstalledAt = json.optLong("wifi_installed_at"),
            wifiInstalledElapsed = json.optLong("wifi_installed_elapsed"),
            wifiInstalledBoot = json.optInt("wifi_installed_boot"),
            confirmPending = json.optBoolean("confirm_pending"),
            connectedAfterInstall = json.optBoolean("connected_after_install"),
            problem = json.optStringOrNull("problem")?.let { Problem.valueOf(it) },
            waitUntil = json.optLong("wait_until"),
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
 * interleave, and no request with the old device credential runs while it
 * is being renewed.
 *
 * Requests with the device credential go through one [EstClient] at a time,
 * closed when the credential is replaced and at the end of every call.
 */
class Enroller(
    private val keys: DeviceKeys,
    private val wifi: WifiInstaller,
    private val store: StateStore,
    private val log: (String) -> Unit = {},
    private val clock: () -> Long = System::currentTimeMillis,
    /** Milliseconds since boot (Android's elapsedRealtime), unaffected by clock changes. */
    private val elapsedClock: () -> Long = { System.nanoTime() / 1_000_000 },
    /** Android's boot count, or 0 when it can't be read. */
    private val bootCount: () -> Int = { 0 },
) {
    enum class Outcome {
        NOT_ENROLLED,
        OK,

        /** A temporary failure; try again soon (with backoff). */
        RETRY,

        /** The server asked to wait until [EnrollmentState.waitUntil]; nothing is sent before then. */
        WAIT,

        /** Refused in a way that retrying soon won't fix; the daily check tries again. */
        LATER,

        /** Needs the user: a new setup link, or the device or user was disabled. */
        STOPPED,
    }

    fun state(): EnrollmentState? = synchronized(LOCK) { store.load() }

    /**
     * Enrolls the device with the code from [link], then gets the first
     * Wi-Fi certificate, for a WPA3-Enterprise-only network if [wpa3].
     * Throws if the device credential can't be obtained; a failure after
     * that is recorded in the state and retried by [maintain].
     */
    fun setup(link: SetupUri, wpa3: Boolean = false): Outcome = synchronized(LOCK) {
        log("Setting up with ${link.serverUrl}")
        closeClient()
        // The server checks attestation against the code as sent in the
        // Authorization header.
        val alias = keys.create(challenge = sha256(link.code.toByteArray(Charsets.US_ASCII)))
        val chain = try {
            val keyPair = keys.keyPair(alias)
            // Without the current credential, if there is one: the server
            // would refuse an expired one in the handshake.
            val chain = EstClient(link.serverUrl, link.caFingerprint).use {
                it.enrollDevice(link.code, Csr.create(keyPair, "eap-enroll"), keys.attestation(alias))
            }
            checkIssued(chain, keyPair.public)
            // Replaces whatever was stored, even a state that can't be read.
            store.save(EnrollmentState(link.serverUrl, link.caFingerprint, alias, chain, wpa3 = wpa3))
            chain
        } catch (e: Exception) {
            // Best effort: a key that stays is deleted by a later check.
            runCatching { keys.delete(alias) }
            throw e
        }
        // The previous enrollment's keys, and any left over.
        deleteOtherKeys(setOf(alias))
        log("Device credential for ${Certs.commonName(chain[0])}, valid until ${chain[0].notAfter}")
        try {
            maintainLocked(renewWifi = true, byUser = true)
        } finally {
            closeClient()
        }
    }

    /**
     * Confirms, renews whatever is due, and retries what failed before.
     * [byUser]: the user asked for it, so a disabled user account is tried
     * again (it may have been enabled since).
     */
    fun maintain(renewWifi: Boolean = false, byUser: Boolean = false): Outcome =
        synchronized(LOCK) {
            try {
                maintainLocked(renewWifi, byUser)
            } catch (e: UnreadableStateException) {
                log(Errors.describe(e))
                Outcome.STOPPED
            } finally {
                closeClient()
            }
        }

    /**
     * Records that Wi-Fi connected to [ssid] through this app's suggestion
     * at [at], [elapsed] milliseconds into boot [boot]. Returns true if that
     * proves the current certificate works, so a [maintain] run should
     * confirm it.
     */
    fun connectionObserved(
        ssid: String,
        at: Long = clock(),
        elapsed: Long = elapsedClock(),
        boot: Int = bootCount(),
    ): Boolean = synchronized(LOCK) {
        val state = store.load() ?: return false
        // A stopped enrollment confirms nothing: the confirmation waits for
        // the user. Nor does a connection to another network.
        if (state.problem != null || state.profile?.ssid != ssid) return false
        if (!state.confirmPending || state.connectedAfterInstall) return state.confirmPending
        // A connection made before the new suggestion was installed could
        // still be reported just after it. Within a boot, the monotonic
        // clock tells when the connection was made; across boots only the
        // boot count can, since the broadcast carries no elapsed time from
        // before the reboot. Without either (an old state, or a phone that
        // won't say), only the wall time remains.
        val installedElapsed = state.wifiInstalledElapsed
        val installedBoot = state.wifiInstalledBoot
        val counted = if (installedElapsed == 0L || installedBoot == 0 || boot == 0) {
            at >= state.wifiInstalledAt + INSTALL_SETTLE_MS
        } else if (boot != installedBoot) {
            boot > installedBoot
        } else {
            elapsed >= installedElapsed + INSTALL_SETTLE_MS
        }
        if (!counted) {
            log("Connection reported too soon after installing the certificate; not counted")
            return false
        }
        store.save(state.copy(connectedAfterInstall = true))
        log("Wi-Fi connected with the new certificate")
        true
    }

    /**
     * Deletes the stored state and the device keys, also when the state
     * can't be read. Removing the suggestion is up to the caller.
     */
    fun forget() = synchronized(LOCK) {
        store.save(null)
        keys.deleteOthers(emptySet())
    }

    /** Best effort: a key that can't be deleted now is deleted by a later check. */
    private fun deleteOtherKeys(keep: Set<String>) {
        try {
            keys.deleteOthers(keep)
        } catch (e: Exception) {
            log("Deleting unused device keys failed: ${Errors.describe(e)}")
        }
    }

    /**
     * [reconnect]: a request answered `401 credential_superseded` came over a
     * connection opened with a credential that has been replaced since. The
     * whole check then runs once more from the stored state, with a new
     * client for the current credential: every step is safe to repeat, and
     * a device credential renewal is meant to be repeated with the same old
     * credential when it failed.
     */
    private fun maintainLocked(renewWifi: Boolean, byUser: Boolean, reconnect: Boolean = true): Outcome {
        var state = store.load() ?: return Outcome.NOT_ENROLLED
        when (state.problem) {
            null -> {}
            Problem.USER_DISABLED -> if (!byUser) return Outcome.STOPPED
            Problem.NEEDS_SETUP, Problem.DISABLED -> return Outcome.STOPPED
        }
        val now = clock()
        if (now < state.waitUntil) {
            log("The server asked for no requests before ${Date(state.waitUntil)}")
            return Outcome.WAIT
        }
        // Keys of a setup or renewal that was interrupted before its state was stored.
        deleteOtherKeys(setOfNotNull(state.deviceAlias, state.previousDeviceAlias))
        try {
            // Before anything else, such as making a key for a renewal that can't work.
            checkNotExpired(state.deviceChain[0])
            // The server answered an authenticated request past its account
            // check. A disabled account (checked again only because the user
            // asked) then counts as enabled, cleared at once so a later
            // failure doesn't bring it back. [retired]: the request was made
            // with the stored credential, so a previous one still waiting to
            // be retired has been retired by it.
            var accountChecked = state.problem != Problem.USER_DISABLED
            fun gotThrough(retired: Boolean = true) {
                if (retired) state = previousCredentialRetired(state)
                if (state.problem == Problem.USER_DISABLED) {
                    state = state.copy(problem = null)
                    store.save(state)
                    log("The account is enabled again")
                }
                accountChecked = true
            }
            // With nothing due, nothing else would be sent at all.
            // wifi/profile is authenticated and checks the account; without a
            // profile on the server (404) it proves nothing.
            if (!accountChecked && client(state).wifiProfile() != null) gotThrough()
            if (state.previousDeviceAlias != null) {
                state = retirePreviousCredential(state)
                // Retired only after an authenticated answer: without a
                // profile the server authenticated the confirmation, so the
                // account passed its check.
                if (state.previousDeviceAlias == null) gotThrough(retired = false)
            }
            // A 400 naming the serial means it isn't a current Wi-Fi
            // certificate of this phone (expired, revoked or unknown to the
            // server): confirming it can never work, so it is replaced
            // below. Any other error, a 400 without such a reason
            // included, is retried like other failures. The
            // confirmation stays pending until that succeeds, so a failed
            // renewal leads here again on the next check.
            var wifiNotCurrent = false
            if (state.confirmPending && state.connectedAfterInstall) {
                try {
                    state = confirmWifi(state)
                    gotThrough()
                } catch (e: EstException) {
                    if (e.status != 400 || e.reason !in SERIAL_NOT_CURRENT) throw e
                    gotThrough()
                    log("Wi-Fi certificate ${state.wifiChain!![0].serialNumber.toString(16)} can't be confirmed; " +
                        "requesting a new one: ${Errors.describe(e)}")
                    wifiNotCurrent = true
                }
            }
            // A renewal that fails over the new key's attestation, or over
            // making the new key, leaves the current credential working:
            // Wi-Fi is renewed with it all the same (wifi/simpleenroll isn't
            // attested), and the renewal's failure decides the outcome.
            var deviceRenewalFailure: Exception? = null
            if (Certs.renewalDue(state.deviceChain[0], now)) {
                try {
                    state = renewDeviceCredential(state)
                    // The request was made with the credential that has just
                    // been replaced; renewDeviceCredential() retires it.
                    gotThrough(retired = false)
                } catch (e: Exception) {
                    if (!keepsCurrentCredential(e)) throw e
                    // The server checks the account before the attestation.
                    if (e is EstException) gotThrough()
                    log("Device credential renewal failed; keeping the current credential: ${Errors.describe(e)}")
                    deviceRenewalFailure = e
                }
            }
            val wifiChain = state.wifiChain
            val profile = state.profile
            val wifiDue = wifiChain == null || Certs.renewalDue(wifiChain[0], now)
            val wifiMissing = wifiChain != null && profile != null && !wifi.isInstalled(profile)
            val wifiReplaced = renewWifi || wifiNotCurrent || wifiDue || (wifiMissing && !state.confirmPending)
            if (wifiReplaced) {
                if (wifiMissing && !renewWifi && !wifiNotCurrent && !wifiDue) {
                    log("Wi-Fi network '${profile!!.ssid}' is not installed; reinstalling")
                }
                state = renewWifi(state)
                gotThrough()
            }
            if (!accountChecked) {
                log("Nothing showed that the account is enabled again (the server has no Wi-Fi profile)")
                return Outcome.STOPPED
            }
            when (val e = deviceRenewalFailure) {
                null -> {}
                is EstException -> return refused(state, e)
                else -> {
                    fail(state, e, null)
                    return Outcome.RETRY
                }
            }
            if (wifiMissing && !wifiReplaced) {
                // The current certificate is unconfirmed (otherwise it was
                // reinstalled above): don't request another until it is due,
                // so repeated removals can't exhaust the server's limit.
                wifi.checkAllowed()
                throw WifiInstallException(
                    "The Wi-Fi network was removed, but not requesting a new certificate while the current one " +
                        "isn't confirmed yet. It is renewed automatically when due.",
                )
            }
            store.save(state.copy(problem = null, waitUntil = 0, lastError = null, lastSuccessAt = clock()))
            return Outcome.OK
        } catch (e: EstException) {
            if (reconnect && isSuperseded(e)) {
                log("The server says the connection's credential was replaced; reconnecting with the current one")
                closeClient()
                return maintainLocked(renewWifi, byUser, reconnect = false)
            }
            return refused(state, e)
        } catch (e: CredentialExpiredException) {
            fail(state, e, Problem.NEEDS_SETUP)
            return Outcome.STOPPED
        } catch (e: MissingDeviceKeyException) {
            // Without the key the credential can't be used, nor renewed.
            fail(state, e, Problem.NEEDS_SETUP)
            return Outcome.STOPPED
        } catch (e: WifiInstallException) {
            // Requesting another certificate soon would most likely fail
            // the same way and only add another valid, unconfirmed one.
            fail(state, e, null)
            return Outcome.LATER
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
        } catch (e: ProviderException) {
            // The Keystore's errors, e.g. from StrongBox, while signing with a device key.
            fail(state, e, null)
            return Outcome.RETRY
        }
    }

    /** What an error answer from the server means for this phone (the server's docs/protocol.md). */
    private fun refused(state: EnrollmentState, e: EstException): Outcome = when {
        // Even a new connection with the current credential got it. Not a
        // refusal of the device: try again later.
        isSuperseded(e) -> {
            fail(state, e, null)
            Outcome.RETRY
        }
        e.status == 401 -> {
            fail(state, e, Problem.NEEDS_SETUP)
            Outcome.STOPPED
        }
        e.status == 403 && e.reason == "user_disabled" -> {
            fail(state, e, Problem.USER_DISABLED)
            Outcome.STOPPED
        }
        // Only device credential renewal is attested. The current
        // credential still works; the daily check tries again, and the
        // expiry warning tells the user if it keeps failing.
        isAttestationRefused(e) -> {
            fail(state, e, null)
            Outcome.LATER
        }
        // device_disabled, credential_reuse, or a server that sends no reason.
        e.status == 403 -> {
            fail(state, e, Problem.DISABLED)
            Outcome.STOPPED
        }
        e.status == 429 -> {
            val seconds = (e.retryAfterSeconds?.takeIf { it > 0 } ?: DEFAULT_WAIT_S).coerceAtMost(MAX_WAIT_S)
            fail(state, e, null, waitUntil = clock() + seconds * 1000)
            Outcome.WAIT
        }
        // A 5xx or a refused attestation may pass on its own; other
        // answers, such as 400 bad_csr or 413 body_too_large, mean the
        // request itself is wrong, so a retry soon would fail the same way.
        e.status >= 500 || isBadAttestation(e) -> {
            fail(state, e, null)
            Outcome.RETRY
        }
        else -> {
            fail(state, e, null)
            Outcome.LATER
        }
    }

    private fun isAttestationRefused(e: EstException) = e.status == 403 && e.reason == "attestation_refused"

    private fun isBadAttestation(e: EstException) = e.status == 400 && e.reason == "bad_attestation"

    /**
     * Whether a failed device credential renewal leaves the current
     * credential usable: the server turned down only the new key's
     * attestation (refused, missing or unusable, or its status list is
     * unavailable), or the phone couldn't make the new key.
     */
    private fun keepsCurrentCredential(e: Exception): Boolean = when (e) {
        is NewDeviceKeyException -> true
        is EstException -> isAttestationRefused(e) || isBadAttestation(e) ||
            (e.status == 502 && e.reason == "attestation_status_unavailable")
        else -> false
    }

    private fun isSuperseded(e: EstException) = e.status == 401 && e.reason == "credential_superseded"

    private fun fail(state: EnrollmentState, e: Exception, problem: Problem?, waitUntil: Long = 0) {
        val message = Errors.describe(e)
        log("Enrollment request failed: $message")
        // The state may have advanced since [state] was read; keep that. A
        // user-disabled account retried by the user stays so until a check
        // gets through.
        val current = store.load() ?: state
        store.save(current.copy(
            problem = problem ?: current.problem,
            waitUntil = waitUntil,
            lastError = message,
            lastErrorAt = clock(),
        ))
    }

    private var client: EstClient? = null
    private var clientCredential: X509Certificate? = null

    /**
     * The client for the stored device credential. Reused within a call,
     * replaced (and the old one closed) when the credential changes. An
     * expired credential isn't offered at all: the server would fail the
     * handshake, and only a new setup link helps.
     */
    private fun client(state: EnrollmentState): EstClient {
        val certificate = state.deviceChain[0]
        checkNotExpired(certificate)
        client?.let { if (clientCredential == certificate) return it }
        closeClient()
        val keyPair = keys.keyPair(state.deviceAlias)
        return EstClient(state.serverUrl, state.caFingerprint, ClientCredential(keyPair.private, state.deviceChain))
            .also { client = it; clientCredential = certificate }
    }

    private fun checkNotExpired(credential: X509Certificate) {
        if (clock() >= credential.notAfter.time) throw CredentialExpiredException(credential.notAfter)
    }

    /** Closes the device credential's client: its TLS sessions are dropped and it refuses further requests. */
    private fun closeClient() {
        client?.close()
        client = null
        clientCredential = null
    }

    /**
     * Uses the new device credential once in a request the server
     * authenticates, which makes it revoke the old one, then deletes the old
     * key. Until this has worked, the old credential stays stored but is
     * never used again.
     *
     * That request is `wifi/profile`. A server without a profile answers it
     * with 404 before authenticating; then the current Wi-Fi certificate is
     * confirmed again, which is harmless once it is confirmed (a refused
     * serial counts too: the server authenticated the request). With an
     * unconfirmed certificate or none, the old credential waits for the
     * next request that gets through.
     *
     * The profile isn't stored here: the state's profile is the one
     * installed in Wi-Fi, and a changed one comes with the next Wi-Fi
     * certificate.
     */
    private fun retirePreviousCredential(state: EnrollmentState): EnrollmentState {
        val client = client(state)
        if (client.wifiProfile() == null) {
            val wifi = state.wifiChain?.get(0)
            if (wifi == null || state.confirmPending) {
                log("The previous device credential isn't retired yet: the server has no Wi-Fi profile")
                return state
            }
            try {
                client.confirmWifi(wifi.serialNumber)
            } catch (e: EstException) {
                if (e.status != 400 || e.reason !in SERIAL_NOT_CURRENT) throw e
            }
        }
        return previousCredentialRetired(state)
    }

    /** The server has seen the current device credential since the renewal, so the old one is revoked. */
    private fun previousCredentialRetired(state: EnrollmentState): EnrollmentState {
        val previous = state.previousDeviceAlias ?: return state
        keys.delete(previous)
        val next = state.copy(previousDeviceAlias = null)
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
        // Always a new key: an attestation challenge is fixed when the key is
        // generated, and the server wants the hash of the credential
        // presented in this request.
        val alias = newDeviceKey { keys.create(challenge = sha256(state.deviceChain[0].encoded)) }
        val next = try {
            val identity = Certs.commonName(state.deviceChain[0]).ifEmpty { "eap-enroll" }
            val (keyPair, csr, attestation) = newDeviceKey {
                val keyPair = keys.keyPair(alias)
                Triple(keyPair, Csr.create(keyPair, identity), keys.attestation(alias))
            }
            val chain = client(state).reenrollDevice(csr, attestation)
            checkIssued(chain, keyPair.public)
            // A failed or lost renewal throws above and leaves the current
            // credential in place: the next check renews again with it, and
            // the server retires what the lost one issued. Only a credential
            // from an answer that arrived is ever stored, and it is stored
            // before the old key goes, so a failed save leaves the old
            // credential usable. The server issued a credential, so the
            // account passed its check: a disabled account is enabled again.
            val next = state.copy(
                deviceAlias = alias,
                deviceChain = chain,
                previousDeviceAlias = state.deviceAlias,
                problem = if (state.problem == Problem.USER_DISABLED) null else state.problem,
            )
            store.save(next)
            if (state.problem == Problem.USER_DISABLED) log("The account is enabled again")
            next
        } catch (e: Exception) {
            // Best effort: a key that stays is deleted by a later check.
            runCatching { keys.delete(alias) }
            throw e
        }
        // The state has the new credential; the keys it replaced go now.
        state.previousDeviceAlias?.let { runCatching { keys.delete(it) } }
        // From here on only the new credential: no connection or TLS session
        // of the old one may be used again.
        closeClient()
        log("New device credential, valid until ${next.deviceChain[0].notAfter}")
        return retirePreviousCredential(next)
    }

    /** Runs a step of making the new device key and its CSR, which happens on the phone only. */
    private fun <T> newDeviceKey(step: () -> T): T = try {
        step()
    } catch (e: Exception) {
        throw NewDeviceKeyException(e)
    }

    private fun renewWifi(state: EnrollmentState): EnrollmentState {
        wifi.checkAllowed()
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
        try {
            wifi.install(profile, state.wpa3, wifiIdentity, keyPair.private, Certs.withoutRoots(chain))
        } catch (e: WifiInstallException) {
            throw e
        } catch (e: Exception) {
            throw WifiInstallException("Installing the Wi-Fi certificate failed: ${e.message}", e)
        }
        val next = state.copy(
            profile = profile,
            wifiChain = chain,
            wifiInstalledAt = clock(),
            wifiInstalledElapsed = elapsedClock(),
            wifiInstalledBoot = bootCount(),
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
        Certs.checkChain(chain)
        // Stored, a credential the phone can't use would replace one that
        // works. A start in the future is left alone: the phone's clock may
        // be a little behind the server's. Every certificate counts: a leaf
        // that is valid now is unusable once an issuer in its chain has
        // expired.
        chain.forEach { cert ->
            check(cert.notBefore.before(cert.notAfter)) {
                "The server's certificate for ${cert.subjectX500Principal} has no valid period"
            }
            check(clock() < cert.notAfter.time) {
                "The server's certificate for ${cert.subjectX500Principal} expired on ${cert.notAfter}"
            }
        }
    }

    companion object {
        private val LOCK = Any()

        /** Connections reported this soon after installing a certificate may predate it. */
        const val INSTALL_SETTLE_MS = 10_000L

        /** `wifi/confirm` reasons for a serial that isn't a current Wi-Fi certificate of this phone. */
        private val SERIAL_NOT_CURRENT = setOf("expired_serial", "revoked_serial", "unknown_serial")

        /** Waits for a 429 without (or with a nonsensical) Retry-After. */
        private const val DEFAULT_WAIT_S = 15 * 60L
        internal const val MAX_WAIT_S = 24 * 3600L

        private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

        /**
         * Whether the setup link can be tried again after [setup] failed with
         * [e], from the order in which the server checks `device/simpleenroll`
         * (the server's docs/protocol.md). Null when it can't be said.
         */
        fun setupLinkAdvice(e: Throwable): String? {
            if (e !is EstException) return null
            return when {
                e.status == 401 -> "The setup link is no longer valid (used, expired or mistyped); a new one is needed."
                e.status == 400 || e.status == 413 || e.reason == "attestation_refused" ||
                    e.reason == "attestation_status_unavailable" ->
                    "The setup link wasn't used up and can be tried again."
                e.status == 403 || e.status == 429 -> "The setup link is used up; a new one is needed."
                e.status >= 500 -> "The setup link may have been used up. Try it again; " +
                    "if the server then says the code is no longer valid, a new link is needed."
                else -> null
            }
        }

        /**
         * Why a Wi-Fi certificate asked for by the user should not be
         * requested now, or null if it may. Every new certificate stays valid
         * until it expires or a newer one is confirmed, and the server allows
         * only a few valid ones per phone; past that it refuses renewals,
         * the automatic ones included.
         */
        fun manualWifiRenewalRefusal(state: EnrollmentState?, now: Long): String? {
            val wifi = state?.wifiChain?.get(0) ?: return null
            // Without a working device credential nothing is requested anyway.
            if (state.problem == Problem.NEEDS_SETUP || state.problem == Problem.DISABLED) return null
            if (!state.confirmPending || state.connectedAfterInstall) return null
            if (Certs.renewalDue(wifi, now)) return null
            return "Not requesting a new Wi-Fi certificate: the current one isn't confirmed yet. " +
                "The server keeps unconfirmed certificates valid and allows only a few per phone. " +
                "Connect to the network with the current one first; " +
                "it is renewed automatically when due."
        }
    }
}

/** The device credential has expired; the server would refuse it in the TLS handshake. Needs a new setup link. */
class CredentialExpiredException(val notAfter: Date) :
    GeneralSecurityException("The device credential expired on $notAfter")

/** The stored enrollment state can't be read; a new setup replaces it. */
class UnreadableStateException(cause: Exception) :
    IllegalStateException("The stored enrollment can't be read: ${cause.javaClass.simpleName}: ${cause.message}", cause)

/** The device credential's key isn't in the keystore any more. Needs a new setup link. */
class MissingDeviceKeyException(alias: String) : GeneralSecurityException("Device key $alias is missing")

/** The phone couldn't make a new device key or its CSR (Keystore or StrongBox errors). */
class NewDeviceKeyException(cause: Exception) :
    GeneralSecurityException("Couldn't make a new device key: ${cause.message}", cause)

object Certs {
    /**
     * The subject's CN as it is, or "" if there is none (or it isn't
     * text); the most specific one (the last in the encoding) if there are
     * several. Read from the DER rather than from a string form of the
     * name, which escapes characters such as `,` and `+`.
     */
    fun commonName(cert: X509Certificate): String {
        val cn = Der.oid("2.5.4.3")
        val values = Der.parse(cert.subjectX500Principal.encoded).children()
            .flatMap { rdn -> rdn.children() }
            .map { it.children() }
            .filter { it.size == 2 && it[0].encoded().contentEquals(cn) }
            .mapNotNull { directoryString(it[1]) }
        return values.lastOrNull() ?: ""
    }

    /** The text of a DirectoryString, or null for a type that isn't one. */
    private fun directoryString(value: Der.Element): String? {
        val bytes = value.content()
        return when (value.tag) {
            0x0c -> String(bytes, Charsets.UTF_8) // UTF8String
            0x13, 0x16 -> String(bytes, Charsets.US_ASCII) // PrintableString, IA5String
            0x14 -> String(bytes, Charsets.ISO_8859_1) // TeletexString, as commonly used
            0x1e -> String(bytes, Charsets.UTF_16BE) // BMPString
            0x1c -> String(bytes, charset("UTF-32BE")) // UniversalString
            else -> null
        }
    }

    /**
     * Checks that each certificate of [chain] is issued and signed by the
     * next one. Throws [IllegalStateException] or a [GeneralSecurityException].
     */
    fun checkChain(chain: List<X509Certificate>) {
        chain.zipWithNext { cert, issuer ->
            check(cert.issuerX500Principal == issuer.subjectX500Principal) {
                "${cert.subjectX500Principal} isn't issued by the next certificate in the chain"
            }
            cert.verify(issuer.publicKey)
        }
    }

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
        if (e is EstException) {
            serverHint(e)?.let { return "$text. $it" }
        }
        if (e is CredentialExpiredException || e is MissingDeviceKeyException || e is UnreadableStateException) {
            return "$text. This phone needs a new setup link."
        }
        // socket() fails with EPERM when the app may not use the network:
        // no INTERNET permission, or a "Network" permission toggled off.
        if (e is java.net.SocketException && e.message?.contains("EPERM") == true) {
            return "$text. The app isn't allowed to use the network; allow it in the app's permissions."
        }
        // Android 17 drops connections to the local network silently
        // without the Nearby devices permission.
        if (e is java.net.SocketTimeoutException) {
            return "$text. If the enrollment server is on the local network, allow the app's " +
                "Nearby devices permission; otherwise check the network or VPN."
        }
        return text
    }

    private fun serverHint(e: EstException): String? = when {
        e.reason == "user_disabled" -> "Your account is disabled on the enrollment server."
        e.reason == "device_disabled" -> "This phone is disabled on the enrollment server; it needs a new setup link."
        e.reason == "credential_reuse" ->
            "The server saw this phone's replaced credential used again and disabled the phone; " +
                "it needs a new setup link."
        e.reason == "attestation_refused" ->
            "The server refused this phone's key attestation: for example a missing security update " +
                "(install it, then try again), an unlocked bootloader, or an operating system or key " +
                "storage it doesn't accept."
        e.reason == "bad_attestation" -> "The server requires key attestation and couldn't use this phone's."
        e.reason == "expired_serial" || e.reason == "revoked_serial" || e.reason == "unknown_serial" ->
            "The server doesn't count this Wi-Fi certificate as current (expired, revoked or unknown)."
        e.reason == "credential_superseded" ->
            "The server says the connection used a replaced credential; the next check reconnects."
        e.status == 429 -> e.retryAfterSeconds?.let {
            // Clamped like the wait itself, so the hint never exceeds the cap.
            "The server asks to wait ${(it.coerceIn(1, Enroller.MAX_WAIT_S) + 59) / 60} minute(s)."
        } ?: "The server asks to wait."
        else -> null
    }
}
