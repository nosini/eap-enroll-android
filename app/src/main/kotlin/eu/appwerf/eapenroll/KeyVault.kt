package eu.appwerf.eapenroll

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.File
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
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
 */
class KeyVault(context: Context) {
    private val dir = context.noBackupFilesDir
    private val encryptedKeyFile = File(dir, "wifi-key.enc")
    private val publicKeyFile = File(dir, "wifi-key.pub")

    /** Whether the wrapping key ended up in StrongBox; null if not generated in this run. */
    var lastWrapKeyInStrongBox: Boolean? = null
        private set

    fun hasKey(): Boolean = encryptedKeyFile.exists() && publicKeyFile.exists()

    fun generate(curve: String): KeyPair {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec(curve))
        val keyPair = generator.generateKeyPair()

        val pkcs8 = keyPair.private.encoded
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, newWrapKey())
            val ciphertext = cipher.doFinal(pkcs8)
            val iv = cipher.iv
            val blob = ByteBuffer.allocate(1 + iv.size + ciphertext.size)
                .put(iv.size.toByte()).put(iv).put(ciphertext).array()
            writeAtomically(encryptedKeyFile, blob)
            writeAtomically(publicKeyFile, keyPair.public.encoded)
        } finally {
            pkcs8.fill(0)
        }
        return keyPair
    }

    fun load(): KeyPair {
        check(hasKey()) { "No stored key" }
        val blob = encryptedKeyFile.readBytes()
        val ivLength = blob[0].toInt()
        val iv = blob.copyOfRange(1, 1 + ivLength)
        val ciphertext = blob.copyOfRange(1 + ivLength, blob.size)

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, wrapKey(), GCMParameterSpec(128, iv))
        val pkcs8 = cipher.doFinal(ciphertext)
        try {
            val factory = KeyFactory.getInstance("EC")
            val privateKey = factory.generatePrivate(PKCS8EncodedKeySpec(pkcs8))
            val publicKey = factory.generatePublic(X509EncodedKeySpec(publicKeyFile.readBytes()))
            return KeyPair(publicKey, privateKey)
        } finally {
            pkcs8.fill(0)
        }
    }

    fun publicKeyEncoded(): ByteArray? =
        if (publicKeyFile.exists()) publicKeyFile.readBytes() else null

    /** Deletes the encrypted key and the wrapping key. */
    fun delete() {
        encryptedKeyFile.delete()
        publicKeyFile.delete()
        keyStore().deleteEntry(WRAP_ALIAS)
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun wrapKey(): SecretKey =
        keyStore().getKey(WRAP_ALIAS, null) as? SecretKey
            ?: throw IllegalStateException("Wrapping key is missing")

    private fun newWrapKey(): SecretKey {
        keyStore().deleteEntry(WRAP_ALIAS)
        return try {
            generateWrapKey(strongBox = true).also { lastWrapKeyInStrongBox = true }
        } catch (e: StrongBoxUnavailableException) {
            generateWrapKey(strongBox = false).also { lastWrapKeyInStrongBox = false }
        }
    }

    private fun generateWrapKey(strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(
            WRAP_ALIAS,
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
        const val WRAP_ALIAS = "wifi-key-wrap"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
