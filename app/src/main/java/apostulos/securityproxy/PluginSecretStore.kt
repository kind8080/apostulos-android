package apostulos.securityproxy

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Stores connector API keys encrypted with an Android Keystore AES-GCM key. */
class PluginSecretStore(context: Context) {
    private val prefs = context.getSharedPreferences("apostulos_plugin_secrets", Context.MODE_PRIVATE)
    private val alias = "apostulos.plugin.secrets.v1"

    fun save(pluginId: String, secret: String) {
        if (secret.isBlank()) {
            prefs.edit().remove(pluginId).apply()
            return
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val encrypted = cipher.doFinal(secret.toByteArray(Charsets.UTF_8))
        val packed = cipher.iv + encrypted
        prefs.edit().putString(pluginId, Base64.encodeToString(packed, Base64.NO_WRAP)).apply()
    }

    fun read(pluginId: String): String? {
        val packed = prefs.getString(pluginId, null) ?: return null
        return runCatching {
            val bytes = Base64.decode(packed, Base64.NO_WRAP)
            require(bytes.size > 12) { "Segredo criptografado inválido" }
            val iv = bytes.copyOfRange(0, 12)
            val ciphertext = bytes.copyOfRange(12, bytes.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, iv))
            String(cipher.doFinal(ciphertext), Charsets.UTF_8)
        }.getOrNull()
    }

    fun remove(pluginId: String) { prefs.edit().remove(pluginId).apply() }

    private fun getOrCreateKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }
}
