package eu.appwerf.eapenroll

import java.util.Date
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Stored state or keys that are broken or left over. */
class LocalStateTest {
    private val server = FakeEstServer()
    private val keys = MemoryKeys()
    private val store = MemoryStore()
    private val now = System.currentTimeMillis()
    private val day = 86_400_000L
    private val deviceCa = server.deviceCa
    private val wifiCa = TestPki.root("Wi-Fi CA")
    private val link = SetupUri.parse(
        "eapenroll://setup?v=1&url=${server.url}&ca=${server.caFingerprint}&code=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
    )

    @After
    fun stop() = server.close()

    private fun enroller(store: StateStore = this.store) = Enroller(keys, RecordingWifi(), store, log = { println(it) }, clock = { now })

    /** The server issues device credentials and is unavailable otherwise. */
    private fun issuingDeviceCredentials() {
        server.answer = {
            if (it.path == "device/simpleenroll") {
                FakeEstServer.issue(it, deviceCa, "alice")
            } else {
                FakeEstServer.Answer(503, "unavailable\n")
            }
        }
    }

    /** Enrolled, with nothing due. */
    private fun enrolled(): EnrollmentState {
        val alias = keys.create()
        val device = TestPki.leaf(deviceCa, "alice", keys.keyPair(alias), Date(now - day), Date(now + 365 * day))
        val wifi = TestPki.leaf(wifiCa, "alice", notBefore = Date(now - day), notAfter = Date(now + 59 * day))
        val state = EnrollmentState(server.url, server.caFingerprint, alias, listOf(device, deviceCa.cert), wifiChain = listOf(wifi, wifiCa.cert))
        store.save(state)
        return state
    }

    @Test
    fun setupReplacesAnUnreadableState() {
        val leftover = keys.create()
        store.json = "{corrupted"
        issuingDeviceCredentials()
        // The Wi-Fi certificate fails; the device credential is stored all the same.
        assertEquals(Enroller.Outcome.RETRY, enroller().setup(link))
        val state = store.load()!!
        assertEquals(keys.created.last().public, state.deviceChain[0].publicKey)
        assertEquals(setOf(state.deviceAlias), keys.keys.keys)
        assertTrue(leftover !in keys.keys)
    }

    @Test
    fun securityModeChosenAtSetupStaysWithTheEnrollment() {
        val profile = WifiProfile("Example Net", "radius.example.org", listOf(TestPki.root("RADIUS CA").cert))
        server.answer = {
            when (it.path) {
                "device/simpleenroll" -> FakeEstServer.issue(it, deviceCa, "alice")
                "wifi/profile" -> FakeEstServer.profile(profile)
                "wifi/simpleenroll" -> FakeEstServer.issue(it, wifiCa, "alice")
                else -> FakeEstServer.Answer(503, "unavailable\n")
            }
        }
        val wifi = RecordingWifi()
        val enroller = Enroller(keys, wifi, store, clock = { now })
        assertEquals(Enroller.Outcome.OK, enroller.setup(link, wpa3 = true))
        assertTrue(store.load()!!.wpa3)
        assertEquals(Enroller.Outcome.OK, enroller.maintain(renewWifi = true, byUser = true))
        assertEquals(listOf(true, true), wifi.installs.map { it.wpa3 })
    }

    @Test
    fun stateStoredWithoutSecurityModeTakesTheGivenOne() {
        val state = enrolled()
        val stored = state.copy(wpa3 = true).toJson()
        assertTrue(EnrollmentState.parse(stored.toString(), wpa3 = false).wpa3)
        stored.remove("wpa3")
        assertTrue(EnrollmentState.parse(stored.toString(), wpa3 = true).wpa3)
        assertFalse(EnrollmentState.parse(stored.toString()).wpa3)
    }

    /** The server issues a device credential, the profile and a Wi-Fi certificate. */
    private fun issuingEverything() {
        val profile = WifiProfile("Example Net", "radius.example.org", listOf(TestPki.root("RADIUS CA").cert))
        server.answer = {
            when (it.path) {
                "device/simpleenroll" -> FakeEstServer.issue(it, deviceCa, "alice", notAfter = Date(now + 365 * day))
                "wifi/profile" -> FakeEstServer.profile(profile)
                "wifi/simpleenroll" -> FakeEstServer.issue(it, wifiCa, "alice", notAfter = Date(now + 60 * day))
                else -> FakeEstServer.Answer(503, "unavailable\n")
            }
        }
    }

    @Test
    fun setupOverAnExpiredEnrollment() {
        val old = enrolled()
        val expired = TestPki.leaf(deviceCa, "alice", keys.keyPair(old.deviceAlias), Date(now - 400 * day), Date(now - day))
        store.save(old.copy(deviceChain = listOf(expired, deviceCa.cert), problem = Problem.NEEDS_SETUP, lastError = "expired"))
        issuingEverything()
        val wifi = RecordingWifi()
        assertEquals(Enroller.Outcome.OK, Enroller(keys, wifi, store, clock = { now }).setup(link))

        assertEquals(listOf("device/simpleenroll", "wifi/profile", "wifi/simpleenroll"), server.requests.map { it.path })
        // No credential with the code (the server would refuse the expired
        // one in the handshake), then only the new one.
        val state = store.load()!!
        assertNull(server.requests[0].clientCertificate)
        server.requests.drop(1).forEach { assertEquals(state.deviceChain[0], it.clientCertificate) }
        assertEquals(keys.created.last().public, state.deviceChain[0].publicKey)
        assertEquals(setOf(state.deviceAlias), keys.keys.keys)
        assertNull(state.problem)
        assertNull(state.lastError)
        assertEquals(wifi.installs.single().chain[0], state.wifiChain!![0])
        assertTrue(state.confirmPending)
    }

    @Test
    fun setupWithAnUnattestedKey() {
        keys.attest = false
        issuingEverything()
        assertEquals(Enroller.Outcome.OK, enroller().setup(link))
        val request = server.requests.first()
        assertEquals("device/simpleenroll", request.path)
        assertEquals("Bearer ${link.code}", request.headers["authorization"])
        assertNull(request.headers["key-attestation"])
        assertNull(store.load()!!.problem)
    }

    @Test
    fun setupReplacesThePreviousEnrollmentsKeys() {
        val old = enrolled()
        issuingDeviceCredentials()
        enroller().setup(link)
        val state = store.load()!!
        assertTrue(state.deviceAlias != old.deviceAlias)
        assertEquals(setOf(state.deviceAlias), keys.keys.keys)
    }

    @Test
    fun unreadableStateStopsChecksAndCanBeRemoved() {
        enrolled()
        store.json = "{corrupted"
        val enroller = enroller()
        assertThrows(UnreadableStateException::class.java) { enroller.state() }
        assertEquals(Enroller.Outcome.STOPPED, enroller.maintain(byUser = true))
        assertTrue(server.requests.isEmpty())
        assertTrue(Notifier.UNREADABLE.contains("new link"))

        enroller.forget()
        assertNull(store.json)
        assertTrue(keys.keys.isEmpty())
    }

    @Test
    fun unknownProblemMakesTheStateUnreadable() {
        enrolled()
        store.json = store.json!!.replace("\"server_url\"", "\"problem\":\"SOMETHING_NEW\",\"server_url\"")
        assertThrows(UnreadableStateException::class.java) { store.load() }
    }

    @Test
    fun keyOfAFailedSaveIsDeleted() {
        val failing = object : StateStore {
            override fun load(): EnrollmentState? = null
            override fun save(state: EnrollmentState?) = throw IllegalStateException("Could not save the enrollment state")
        }
        issuingDeviceCredentials()
        assertThrows(IllegalStateException::class.java) { enroller(failing).setup(link) }
        assertTrue(keys.keys.isEmpty())
    }

    @Test
    fun missingDeviceKeyNeedsSetup() {
        val state = enrolled()
        keys.delete(state.deviceAlias)
        server.answer = { FakeEstServer.Answer(503, "unavailable\n") }
        assertEquals(Enroller.Outcome.STOPPED, enroller().maintain(renewWifi = true, byUser = true))
        assertTrue(server.requests.isEmpty())
        val after = store.load()!!
        assertEquals(Problem.NEEDS_SETUP, after.problem)
        assertTrue(after.lastError!!.contains("new setup link"))
    }

    /** Just after a device credential renewal: the previous key is still stored. */
    private fun renewedJustNow(confirmPending: Boolean = false, wifi: Boolean = true): EnrollmentState {
        val state = enrolled()
        val previous = keys.create()
        val next = state.copy(
            previousDeviceAlias = previous,
            profile = WifiProfile("Example Net", "radius.example.org", listOf(TestPki.root("RADIUS CA").cert)),
            confirmPending = confirmPending,
            wifiChain = if (wifi) state.wifiChain else null,
        )
        store.save(next)
        return next
    }

    @Test
    fun profileRetiresThePreviousCredentialButIsNotStored() {
        val state = renewedJustNow()
        val changed = WifiProfile("Other Net", "radius.example.org", listOf(TestPki.root("Other RADIUS CA").cert))
        server.answer = { FakeEstServer.profile(changed) }
        assertEquals(Enroller.Outcome.OK, enroller().maintain())
        val after = store.load()!!
        assertNull(after.previousDeviceAlias)
        assertEquals(setOf(state.deviceAlias), keys.keys.keys)
        // What Wi-Fi has installed; the next Wi-Fi certificate brings the new profile.
        assertEquals(state.profile, after.profile)
    }

    @Test
    fun withoutProfileAConfirmationRetiresThePreviousCredential() {
        val state = renewedJustNow()
        server.answer = { if (it.path == "wifi/profile") FakeEstServer.Answer(404) else FakeEstServer.Answer(204) }
        assertEquals(Enroller.Outcome.OK, enroller().maintain())
        assertEquals(listOf("wifi/profile", "wifi/confirm"), server.requests.map { it.path })
        assertEquals(state.wifiChain!![0].serialNumber.toString(16), String(server.requests[1].body))
        assertNull(store.load()!!.previousDeviceAlias)
        assertEquals(setOf(state.deviceAlias), keys.keys.keys)
    }

    @Test
    fun withoutProfileOrConfirmedCertificateThePreviousCredentialWaits() {
        val state = renewedJustNow(confirmPending = true)
        server.answer = { FakeEstServer.Answer(404) }
        assertEquals(Enroller.Outcome.OK, enroller().maintain())
        assertEquals(listOf("wifi/profile"), server.requests.map { it.path })
        assertEquals(state.previousDeviceAlias, store.load()!!.previousDeviceAlias)
        assertEquals(setOf(state.deviceAlias, state.previousDeviceAlias), keys.keys.keys)
    }

    @Test
    fun aWifiCertificateRetiresThePreviousCredential() {
        val state = renewedJustNow(wifi = false)
        server.answer = {
            when (it.path) {
                "wifi/simpleenroll" -> FakeEstServer.issue(it, wifiCa, "alice")
                else -> FakeEstServer.Answer(404)
            }
        }
        assertEquals(Enroller.Outcome.OK, enroller().maintain())
        assertEquals(listOf("wifi/profile", "wifi/profile", "wifi/simpleenroll"), server.requests.map { it.path })
        assertNull(store.load()!!.previousDeviceAlias)
        assertEquals(setOf(state.deviceAlias), keys.keys.keys)
    }

    @Test
    fun leftoverKeysAreDeleted() {
        val state = enrolled()
        val leftover = keys.create()
        assertEquals(Enroller.Outcome.OK, enroller().maintain())
        assertTrue(server.requests.isEmpty())
        assertEquals(setOf(state.deviceAlias), keys.keys.keys)
        assertTrue(leftover !in keys.keys)
    }
}

/** Which connections count as proof that the newly installed certificate works. */
class ConnectionObservationTest {
    private val keys = MemoryKeys()
    private val store = MemoryStore()
    private var wall = 1_700_000_000_000L
    private var elapsed = 900_000L
    private var boot = 3
    private val enroller = Enroller(
        keys, RecordingWifi(), store, log = { println(it) },
        clock = { wall }, elapsedClock = { elapsed }, bootCount = { boot },
    )

    private fun awaitingConfirmation(installedAt: Long, installedElapsed: Long, installedBoot: Int = boot) {
        val ca = TestPki.root("Test CA")
        val alias = keys.create()
        store.save(EnrollmentState(
            "https://enroll.example.org", "ab".repeat(32), alias,
            listOf(TestPki.leaf(ca, "alice", keys.keyPair(alias))),
            wifiInstalledAt = installedAt, wifiInstalledElapsed = installedElapsed,
            wifiInstalledBoot = installedBoot, confirmPending = true,
        ))
    }

    @Test
    fun aClockJumpForwardDoesNotConfirmTooSoon() {
        awaitingConfirmation(wall, elapsed)
        wall += 60_000
        elapsed += 1_000
        assertFalse(enroller.connectionObserved(wall, elapsed, boot))
        assertTrue(store.load()!!.confirmPending)
    }

    @Test
    fun aClockJumpBackStillConfirms() {
        awaitingConfirmation(wall, elapsed)
        wall -= 60_000
        elapsed += Enroller.INSTALL_SETTLE_MS
        assertTrue(enroller.connectionObserved(wall, elapsed, boot))
        assertTrue(store.load()!!.connectedAfterInstall)
    }

    @Test
    fun aConnectionAfterALaterBootCounts() {
        // elapsedRealtime started again with the boot; the boot count says
        // the connection is from after the install.
        awaitingConfirmation(wall, 900_000)
        assertTrue(enroller.connectionObserved(wall + 1_000, 5_000, boot + 1))
    }

    @Test
    fun aConnectionFromAnEarlierBootDoesNotCount() {
        awaitingConfirmation(wall, elapsed)
        assertFalse(enroller.connectionObserved(wall + 60_000, elapsed + 60_000, boot - 1))
        assertTrue(store.load()!!.confirmPending)
    }

    @Test
    fun aBroadcastFromBeforeTheInstallHandledLaterDoesNotCount() {
        // ConnectionReceiver handed a broadcast from just before the install
        // to a job, which ran after it: same boot, an elapsed time smaller
        // than the install's.
        awaitingConfirmation(wall, elapsed)
        assertFalse(enroller.connectionObserved(wall + 60_000, elapsed - 1_000, boot))
    }

    @Test
    fun anUnknownBootCountUsesTheWallClock() {
        awaitingConfirmation(wall, elapsed)
        assertFalse(enroller.connectionObserved(wall + Enroller.INSTALL_SETTLE_MS - 1, 5_000, 0))
        assertTrue(enroller.connectionObserved(wall + Enroller.INSTALL_SETTLE_MS, 5_000, 0))

        // The state stored before the boot count was kept is unknown too.
        awaitingConfirmation(wall, elapsed, installedBoot = 0)
        assertFalse(enroller.connectionObserved(wall + Enroller.INSTALL_SETTLE_MS - 1, 5_000, boot))
        assertTrue(enroller.connectionObserved(wall + Enroller.INSTALL_SETTLE_MS, 5_000, boot))
    }

    @Test
    fun aStateFromBeforeTheElapsedClockUsesTheWallClock() {
        awaitingConfirmation(wall, installedElapsed = 0)
        assertFalse(enroller.connectionObserved(wall + Enroller.INSTALL_SETTLE_MS - 1, 5_000, boot))
        assertTrue(enroller.connectionObserved(wall + Enroller.INSTALL_SETTLE_MS, 5_000, boot))
    }
}
