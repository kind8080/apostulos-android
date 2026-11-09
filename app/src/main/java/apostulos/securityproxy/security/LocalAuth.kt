package apostulos.securityproxy.security

import java.security.MessageDigest

object LocalAuth {
    private const val PASSWORD_SHA256 = "01230673abfb14f331a58bdc99bb309ee12acfd3ed1304d729b3e06629a3a54f"
    private val allowedUsers = setOf("seteowl", "kind", "the_symon0")

    fun authenticate(username: String, password: String): Boolean {
        if (username.trim() !in allowedUsers) return false
        val digest = MessageDigest.getInstance("SHA-256").digest(password.toByteArray(Charsets.UTF_8))
        val actual = digest.joinToString("") { "%02x".format(it) }
        return MessageDigest.isEqual(actual.toByteArray(), PASSWORD_SHA256.toByteArray())
    }
}
