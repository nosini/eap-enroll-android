package eu.appwerf.eapenroll

import java.security.KeyPair
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.X509Certificate
import org.json.JSONObject

/**
 * Device keys in memory. Keys made with a challenge get a stand-in
 * attestation chain (a certificate for the key, then a fake root); servers
 * that don't require attestation ignore it.
 */
class MemoryKeys : DeviceKeys {
    val keys = HashMap<String, KeyPair>()
    val challenges = ArrayList<ByteArray?>()

    /** Every key made, in order, including deleted ones. */
    val created = ArrayList<KeyPair>()
    private val attestations = HashMap<String, List<ByteArray>>()
    private val attestationRoot = TestPki.root("Fake Attestation Root")
    private var next = 0

    override fun create(challenge: ByteArray?): String {
        val alias = "device-${next++}"
        val keyPair = TestPki.keyPair("secp256r1")
        keys[alias] = keyPair
        created += keyPair
        challenges += challenge
        if (challenge != null) {
            attestations[alias] = listOf(
                TestPki.leaf(attestationRoot, "Android Keystore Key", keyPair).encoded,
                attestationRoot.cert.encoded,
            )
        }
        return alias
    }

    override fun keyPair(alias: String) = keys[alias] ?: throw IllegalStateException("no key $alias")

    override fun attestation(alias: String): List<ByteArray>? = attestations[alias]

    override fun delete(alias: String) {
        keys.remove(alias)
        attestations.remove(alias)
    }
}

/** Stores JSON, so every step also goes through the state serialisation. */
class MemoryStore : StateStore {
    var json: String? = null

    override fun load() = json?.let { EnrollmentState.fromJson(JSONObject(it)) }

    override fun save(state: EnrollmentState?) {
        json = state?.toJson()?.toString()
    }
}

class Install(val profile: WifiProfile, val identity: String, val key: PrivateKey, val chain: List<X509Certificate>)

class RecordingWifi : WifiInstaller {
    val installs = ArrayList<Install>()

    override fun install(profile: WifiProfile, identity: String, privateKey: PrivateKey, chain: List<X509Certificate>) {
        installs += Install(profile, identity, privateKey, chain)
    }
}

fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
