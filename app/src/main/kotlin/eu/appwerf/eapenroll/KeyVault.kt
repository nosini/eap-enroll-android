package eu.appwerf.eapenroll

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.ProviderException
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Holds the Wi-Fi key between generation and the hand-over to Wi-Fi.
 *
 * The key pair is generated in software, because Wi-Fi can only import a
 * key whose encoding it can read. At rest, the PKCS#8 private key is
 * encrypted with AES-GCM under a non-exportable Android Keystore key; the
 * plaintext is never written to disk.
 *
 * Everything about one key (the wrapping key's alias, the encrypted key and
 * the public key) is in one file, replaced with a single rename. A new key
 * gets a new wrapping key, and the previous one is deleted only once the new
 * file is in place, so a failed or interrupted generation leaves the
 * previous key usable.
 */
class KeyVault(context: Context) {
    private val dir = context.noBackupFilesDir
    private val file = File(dir, "wifi-key")

    // An older layout: two files and a fixed alias.
    private val legacyEncryptedKeyFile = File(dir, "wifi-key.enc")
    private val legacyPublicKeyFile = File(dir, "wifi-key.pub")

    /** Whether the wrapping key ended up in StrongBox; null if not generated in this run. */
    var lastWrapKeyInStrongBox: Boolean? = null
        private set

    fun hasKey(): Boolean = file.exists() || (legacyEncryptedKeyFile.exists() && legacyPublicKeyFile.exists())

    fun generate(curve: String): KeyPair {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec(curve))
        val keyPair = generator.generateKeyPair()

        val alias = WRAP_PREFIX + UUID.randomUUID()
        val pkcs8 = keyPair.private.encoded
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, newWrapKey(alias))
            val ciphertext = cipher.doFinal(pkcs8)
            writeAtomically(file, StoredKey(alias, cipher.iv, ciphertext, keyPair.public.encoded).encode())
        } catch (e: Exception) {
            runCatching { keyStore().deleteEntry(alias) }
            throw e
        } finally {
            pkcs8.fill(0)
        }
        // The new key is in place; what belonged to the previous one goes.
        legacyEncryptedKeyFile.delete()
        legacyPublicKeyFile.delete()
        runCatching { deleteWrapKeysExcept(alias) }
        return keyPair
    }

    fun load(): KeyPair {
        val stored = stored() ?: throw IllegalStateException("No stored key")
        val wrapKey = keyStore().getKey(stored.alias, null) as? SecretKey
            ?: throw IllegalStateException("Wrapping key is missing")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, wrapKey, GCMParameterSpec(128, stored.iv))
        val pkcs8 = cipher.doFinal(stored.ciphertext)
        try {
            val factory = KeyFactory.getInstance("EC")
            val privateKey = factory.generatePrivate(PKCS8EncodedKeySpec(pkcs8))
            val publicKey = factory.generatePublic(X509EncodedKeySpec(stored.publicKey))
            return KeyPair(publicKey, privateKey)
        } finally {
            pkcs8.fill(0)
        }
    }

    fun publicKeyEncoded(): ByteArray? = runCatching { stored()?.publicKey }.getOrNull()

    /** Deletes the encrypted key and the wrapping keys. */
    fun delete() {
        file.delete()
        legacyEncryptedKeyFile.delete()
        legacyPublicKeyFile.delete()
        deleteWrapKeysExcept(null)
    }

    private fun stored(): StoredKey? = when {
        file.exists() -> StoredKey.decode(file.readBytes())
        legacyEncryptedKeyFile.exists() && legacyPublicKeyFile.exists() -> {
            val blob = legacyEncryptedKeyFile.readBytes()
            val ivLength = blob[0].toInt()
            StoredKey(
                LEGACY_WRAP_ALIAS,
                blob.copyOfRange(1, 1 + ivLength),
                blob.copyOfRange(1 + ivLength, blob.size),
                legacyPublicKeyFile.readBytes(),
            )
        }
        else -> null
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun deleteWrapKeysExcept(keep: String?) {
        val store = keyStore()
        store.aliases().toList()
            .filter { (it.startsWith(WRAP_PREFIX) || it == LEGACY_WRAP_ALIAS) && it != keep }
            .forEach { store.deleteEntry(it) }
    }

    /** StrongBox if it works, otherwise the TEE: StrongBox can fail for other reasons than being absent. */
    private fun newWrapKey(alias: String): SecretKey = try {
        generateWrapKey(alias, strongBox = true).also { lastWrapKeyInStrongBox = true }
    } catch (e: Exception) {
        if (e !is GeneralSecurityException && e !is ProviderException) throw e
        runCatching { keyStore().deleteEntry(alias) }
        generateWrapKey(alias, strongBox = false).also { lastWrapKeyInStrongBox = false }
    }

    private fun generateWrapKey(alias: String, strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setIsStrongBoxBacked(strongBox)
            .build()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(spec)
        return generator.generateKey()
    }

    private fun writeAtomically(file: File, data: ByteArray) {
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeBytes(data)
        check(tmp.renameTo(file)) { "Could not write ${file.name}" }
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val WRAP_PREFIX = "wifi-key-wrap-"
        const val LEGACY_WRAP_ALIAS = "wifi-key-wrap"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}

/** What [KeyVault] stores about one key, in one file. */
class StoredKey(val alias: String, val iv: ByteArray, val ciphertext: ByteArray, val publicKey: ByteArray) {
    fun encode(): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { data ->
            data.writeByte(VERSION)
            for (field in listOf(alias.toByteArray(Charsets.UTF_8), iv, ciphertext, publicKey)) {
                data.writeInt(field.size)
                data.write(field)
            }
        }
        return out.toByteArray()
    }

    companion object {
        private const val VERSION = 1
        private const val MAX_FIELD = 64 * 1024

        /** Throws [IllegalArgumentException] for anything but a complete, well-formed file. */
        fun decode(bytes: ByteArray): StoredKey {
            val buffer = ByteBuffer.wrap(bytes)
            fun field(): ByteArray {
                require(buffer.remaining() >= 4) { "Stored key file is truncated" }
                val size = buffer.int
                require(size in 0..minOf(MAX_FIELD, buffer.remaining())) { "Stored key file is truncated" }
                return ByteArray(size).also { buffer.get(it) }
            }
            require(buffer.hasRemaining() && buffer.get().toInt() == VERSION) { "Unknown stored key format" }
            val key = StoredKey(String(field(), Charsets.UTF_8), field(), field(), field())
            require(!buffer.hasRemaining()) { "Trailing data in the stored key file" }
            return key
        }
    }
}
