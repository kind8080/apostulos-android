package apostulos.securityproxy.scan

import android.content.Context
import apostulos.securityproxy.data.Finding
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.security.MessageDigest

data class DefacementResult(
    val summary: String,
    val hash: String,
    val baselineExists: Boolean,
    val changed: Boolean,
    val indicators: List<String>
)

object DefacementScanner {

    private const val MAX_BYTES = 1024 * 1024
    private const val TIMEOUT = 10000

    fun inspect(
        context: Context,
        rawUrl: String,
        saveBaseline: Boolean
    ): Pair<DefacementResult, List<Finding>> {

        val findings = mutableListOf<Finding>()
        val preferences = context.getSharedPreferences(
            "apostulos_defacement_baselines",
            Context.MODE_PRIVATE
        )

        val url = URL(rawUrl.trim())

        validatePublicUrl(url)

        var connection = url.openConnection() as HttpURLConnection
        connection.instanceFollowRedirects = false
        connection.connectTimeout = TIMEOUT
        connection.readTimeout = TIMEOUT
        connection.setRequestProperty("User-Agent", "APOSTULOS-DEFACE/1.0")

        try {
            var currentUrl = url
            var redirects = 0

            while (true) {
                connection.connect()

                val status = connection.responseCode

                if (status in 300..399) {
                    require(redirects < 3) {
                        "Limite de redirecionamentos atingido."
                    }

                    val location = connection.getHeaderField("Location")
                        ?: error("Redirecionamento sem destino.")

                    val nextUrl = URL(currentUrl, location)

                    require(nextUrl.host.equals(currentUrl.host, true)) {
                        "Redirecionamento para outro domínio bloqueado."
                    }

                    require(nextUrl.protocol == currentUrl.protocol &&
                        nextUrl.port.let { if (it == -1) defaultPort(nextUrl.protocol) else it } ==
                        currentUrl.port.let { if (it == -1) defaultPort(currentUrl.protocol) else it }) {
                        "Mudança de protocolo ou porta bloqueada."
                    }

                    validatePublicUrl(nextUrl)

                    connection.disconnect()
                    currentUrl = nextUrl
                    connection = currentUrl.openConnection() as HttpURLConnection
                    connection.instanceFollowRedirects = false
                    connection.connectTimeout = TIMEOUT
                    connection.readTimeout = TIMEOUT
                    connection.setRequestProperty(
                        "User-Agent",
                        "APOSTULOS-DEFACE/1.0"
                    )
                    redirects++
                    continue
                }

                require(status in 200..299) {
                    "O servidor respondeu HTTP $status."
                }

                val contentType = connection.contentType.orEmpty()
                require(
                    contentType.contains("text/html", true) ||
                    contentType.contains("text/plain", true) ||
                    contentType.contains("application/xhtml+xml", true)
                ) {
                    "O endereço não retornou conteúdo HTML ou texto."
                }

                val output = java.io.ByteArrayOutputStream()

                connection.inputStream.use { input ->
                    val buffer = ByteArray(4096)

                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break

                        require(output.size() + count <= MAX_BYTES) {
                            "Página excede o limite de 1 MB."
                        }

                        output.write(buffer, 0, count)
                    }
                }

                val content = output.toString("UTF-8")
                val normalized = content.replace(Regex("""\s+"""), " ").trim()
                val hash = sha256(normalized)

                val baselineKey = sha256(url.toString().toByteArray())
                val previousHash = preferences.getString(baselineKey, null)
                val baselineExists = previousHash != null
                val changed = baselineExists && previousHash != hash

                val indicators = mutableListOf<String>()

                if (Regex("""(?i)<script[^>]+src=["']https?://""").containsMatchIn(content)) {
                    indicators.add("Script externo encontrado.")
                }

                if (Regex("""(?i)<iframe[^>]+src=""").containsMatchIn(content)) {
                    indicators.add("Iframe encontrado.")
                }

                if (
                    Regex(
                        """(?i)hacked by|owned by|site hacked|pwned by"""
                    ).containsMatchIn(content)
                ) {
                    indicators.add("Texto associado a mensagens de defacement encontrado.")
                }

                if (Regex("""(?i)document\.write\s*\(""").containsMatchIn(content)) {
                    indicators.add("Uso de document.write encontrado.")
                }

                if (saveBaseline) {
                    preferences.edit().putString(baselineKey, hash).apply()
                }

                if (changed) {
                    findings.add(
                        createFinding(
                            url.toString(),
                            "Alteração no conteúdo da página",
                            "O SHA-256 atual é diferente da referência salva. Isso não comprova invasão."
                        )
                    )
                }

                indicators.forEach { indicator ->
                    findings.add(
                        createFinding(
                            url.toString(),
                            indicator,
                            "Indicador heurístico encontrado. É necessária análise manual."
                        )
                    )
                }

                val summary = when {
                    saveBaseline -> "Referência de integridade salva."
                    changed -> "Alteração detectada em relação à referência."
                    !baselineExists -> "Nenhuma referência anterior encontrada."
                    else -> "Nenhuma alteração detectada na comparação."
                }

                return Pair(
                    DefacementResult(
                        summary,
                        hash,
                        baselineExists,
                        changed,
                        indicators
                    ),
                    findings
                )
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun validatePublicUrl(url: URL) {
        require(url.protocol == "http" || url.protocol == "https") {
            "Somente URLs HTTP e HTTPS são permitidas."
        }

        require(url.userInfo == null && !url.host.isNullOrBlank()) {
            "URL inválida."
        }

        val addresses = InetAddress.getAllByName(url.host)
        require(addresses.isNotEmpty() && addresses.none { isPrivate(it) }) {
            "Endereço privado ou local não permitido."
        }
    }

    private fun defaultPort(protocol: String): Int =
        if (protocol == "https") 443 else 80

    private fun isPrivate(address: InetAddress): Boolean {
        return address.isAnyLocalAddress ||
            address.isLoopbackAddress ||
            address.isLinkLocalAddress ||
            address.isSiteLocalAddress ||
            address.isMulticastAddress
    }

    private fun sha256(value: String): String {
        return sha256(value.toByteArray(Charsets.UTF_8))
    }

    private fun sha256(bytes: ByteArray): String {
        return MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { "%02x".format(it) }
    }

    private fun createFinding(
        target: String,
        title: String,
        evidence: String
    ): Finding {
        return Finding(
            target = target,
            title = title,
            category = "DEFACEMENT",
            severity = "MEDIUM",
            confidence = "LOW",
            evidence = evidence,
            recommendedTool = "APOSTULOS DEFACE",
            remediation = "Verifique as alterações e compare com uma versão confiável do site.",
            referenceUrl = "",
            status = "Aberta",
            createdAt = System.currentTimeMillis()
        )
    }
}
