package apostulos.securityproxy.scan

import android.content.Context
import apostulos.securityproxy.data.Finding
import okhttp3.Request
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

        var currentUrl = NetworkTargetValidator.validate(rawUrl.trim())
        val originalUrl = currentUrl
        var redirects = 0

        while (true) {
            val request = Request.Builder()
                .url(currentUrl)
                .header("User-Agent", "APOSTULOS-DEFACE/1.0")
                .get()
                .build()

            val response = SafeHttpClient.client.newCall(request).execute()

            try {
                val status = response.code

                if (status in 300..399) {
                    require(redirects < 3) {
                        "Limite de redirecionamentos atingido."
                    }

                    val location = response.header("Location")
                        ?: error("Redirecionamento sem destino.")

                    val nextUrl = URL(currentUrl, location)

                    require(nextUrl.host.equals(currentUrl.host, true)) {
                        "Redirecionamento para outro domínio bloqueado."
                    }

                    require(
                        nextUrl.protocol == currentUrl.protocol &&
                        effectivePort(nextUrl) == effectivePort(currentUrl)
                    ) {
                        "Mudança de protocolo ou porta bloqueada."
                    }

                    currentUrl = NetworkTargetValidator.validate(
                        nextUrl.toString()
                    )

                    redirects++
                    continue
                }

                require(status in 200..299) {
                    "O servidor respondeu HTTP $status."
                }

                val contentType = response.header("Content-Type").orEmpty()

                require(
                    contentType.contains("text/html", true) ||
                    contentType.contains("text/plain", true) ||
                    contentType.contains("application/xhtml+xml", true)
                ) {
                    "O endereço não retornou conteúdo HTML ou texto."
                }

                val output = java.io.ByteArrayOutputStream()
                val input = response.body?.byteStream()
                    ?: error("Resposta sem conteúdo.")

                input.use {
                    val buffer = ByteArray(4096)

                    while (true) {
                        val count = it.read(buffer)
                        if (count < 0) break

                        require(output.size() + count <= MAX_BYTES) {
                            "Página excede o limite de 1 MB."
                        }

                        output.write(buffer, 0, count)
                    }
                }

                val content = String(output.toByteArray(), Charsets.UTF_8)
                val normalized = content.replace(
                    Regex("""\s+"""), " "
                ).trim()

                val hash = sha256(normalized)

                val baselineKey = sha256(originalUrl.toString().toByteArray())
                val previousHash = preferences.getString(baselineKey, null)
                val baselineExists = previousHash != null
                val changed = baselineExists && previousHash != hash

                val indicators = mutableListOf<String>()

                if (Regex("""(?i)<script[^>]+src=["']https?://""")
                        .containsMatchIn(content)) {
                    indicators.add("Script externo encontrado.")
                }

                if (Regex("""(?i)<iframe[^>]+src=""")
                        .containsMatchIn(content)) {
                    indicators.add("Iframe encontrado.")
                }

                if (Regex("""(?i)hacked by|owned by|site hacked|pwned by""")
                        .containsMatchIn(content)) {
                    indicators.add(
                        "Texto associado a mensagens de defacement encontrado."
                    )
                }

                if (Regex("""(?i)document\.write\s*\(""")
                        .containsMatchIn(content)) {
                    indicators.add("Uso de document.write encontrado.")
                }

                if (saveBaseline) {
                    preferences.edit()
                        .putString(baselineKey, hash)
                        .apply()
                }

                if (changed) {
                    findings.add(
                        createFinding(
                            originalUrl.toString(),
                            "Alteração no conteúdo da página",
                            "O SHA-256 atual é diferente da referência salva. Isso não comprova invasão."
                        )
                    )
                }

                indicators.forEach { indicator ->
                    findings.add(
                        createFinding(
                            originalUrl.toString(),
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
            } finally {
                response.close()
            }
        }
    }

    private fun effectivePort(url: URL): Int =
        if (url.port == -1) defaultPort(url.protocol) else url.port

    private fun defaultPort(protocol: String): Int =
        if (protocol == "https") 443 else 80

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
