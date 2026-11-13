package apostulos.securityproxy

import android.content.Context
import android.net.Uri
import apostulos.securityproxy.data.Finding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.MediaType.Companion.toMediaType
import org.json.JSONArray
import org.json.JSONObject
import java.net.URL
import java.net.URLEncoder

object ExternalPluginConnector {
    data class ZapResult(val findings: List<Finding>, val summary: String)
    data class MobSfResult(val findings: List<Finding>, val summary: String, val scanHash: String)

    suspend fun test(engine: String, baseUrl: String, secret: String?): String = withContext(Dispatchers.IO) {
        val base = validateBase(baseUrl)
        val (path, header, headerValue) = when (engine) {
            "zap_remote" -> Triple("/JSON/core/view/version/" + if (!secret.isNullOrBlank()) "?apikey=${encode(secret)}" else "", null, null)
            "mobsf_remote" -> Triple("/api/v1/scans", "Authorization", secret.orEmpty())
            "nmap_agent" -> Triple("/health", "X-APOSTULOS-Agent", "1")
            else -> error("Este plugin não é um conector remoto")
        }
        require(engine == "zap_remote" || !secret.isNullOrBlank() || engine == "nmap_agent") { "Informe a API key do serviço" }
        val body = request(base + path, "GET", header, headerValue)
        when (engine) {
            "zap_remote" -> "Conectado ao OWASP ZAP • ${JSONObject(body).optString("version", "versão não informada")}"
            "mobsf_remote" -> "Conectado ao MobSF • API respondeu"
            "nmap_agent" -> "Agente Nmap respondeu • health check APOSTULOS detectado"
            else -> "Conexão verificada"
        }
    }

    /** Reads existing ZAP passive-scan alerts only. It never starts an active scan. */
    suspend fun fetchZapPassiveAlerts(baseUrl: String, secret: String?, targetFilter: String = ""): ZapResult = withContext(Dispatchers.IO) {
        val base = validateBase(baseUrl)
        val key = if (!secret.isNullOrBlank()) "&apikey=${encode(secret)}" else ""
        val body = request("$base/JSON/core/view/alerts/?start=0&count=100$key", "GET")
        val alerts = JSONObject(body).optJSONArray("alerts") ?: JSONArray()
        val items = mutableListOf<Finding>()
        for (i in 0 until minOf(alerts.length(), 100)) {
            val a = alerts.optJSONObject(i) ?: continue
            val url = a.optString("url", "")
            if (targetFilter.isNotBlank() && !url.contains(targetFilter, ignoreCase = true)) continue
            val risk = a.optString("risk", "Informational")
            val severity = when (risk.lowercase()) {
                "high" -> "HIGH"; "medium" -> "MEDIUM"; "low" -> "LOW"; else -> "INFO"
            }
            items += Finding(
                target = url.ifBlank { "OWASP ZAP" },
                title = a.optString("name", "Alerta ZAP"),
                category = "OWASP ZAP • passivo",
                severity = severity,
                confidence = "Informação reportada pelo ZAP; requer validação manual",
                evidence = listOf(a.optString("description"), a.optString("param").takeIf { it.isNotBlank() }?.let { "Parâmetro: $it" }, a.optString("reference").takeIf { it.isNotBlank() }?.let { "Referência: $it" }).filterNotNull().filter { it.isNotBlank() }.joinToString("\n").take(4000),
                recommendedTool = "OWASP ZAP / revisão manual",
                remediation = a.optString("solution", "Revise a recomendação do alerta no OWASP ZAP.").take(3000),
                referenceUrl = a.optString("reference", "")
            )
        }
        ZapResult(items, "ZAP: ${items.size} alerta(s) passivo(s) importado(s) de até 100 registros; nenhum active scan foi iniciado.")
    }

    /** Uploads only the APK explicitly selected by the user, then requests MobSF static analysis. */
    suspend fun analyzeApkWithMobSf(context: Context, uri: Uri, baseUrl: String, apiKey: String): MobSfResult = withContext(Dispatchers.IO) {
        require(apiKey.isNotBlank()) { "Configure a API key do MobSF" }
        val base = validateBase(baseUrl)
        val originalName = queryDisplayName(context, uri).ifBlank { "selected.apk" }
        require(originalName.endsWith(".apk", ignoreCase = true)) { "Selecione um arquivo com extensão .apk" }
        val name = originalName.replace(Regex("[^A-Za-z0-9._-]"), "_")
        val uploadUrl = "$base/api/v1/upload"
        val apkBody = object : okhttp3.RequestBody() {
            override fun contentType() =
                "application/vnd.android.package-archive".toMediaType()

            override fun contentLength(): Long = -1L

            override fun writeTo(sink: okio.BufferedSink) {
                context.contentResolver.openInputStream(uri)?.use { input ->
                    val buffer = ByteArray(32 * 1024)
                    var total = 0L

                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break

                        total += count
                        require(total <= 250L * 1024L * 1024L) {
                            "APK excede o limite de envio de 250 MB"
                        }

                        sink.write(buffer, 0, count)
                    }
                } ?: error("Não foi possível abrir o APK selecionado")
            }
        }

        val multipartBody = okhttp3.MultipartBody.Builder()
            .setType(okhttp3.MultipartBody.FORM)
            .addFormDataPart("file", name, apkBody)
            .build()

        val uploadRequest = Request.Builder()
            .url(uploadUrl)
            .header("Authorization", apiKey)
            .header("Accept", "application/json")
            .post(multipartBody)
            .build()

        val uploadBody = PluginHttpClient.clientFor(URL(uploadUrl))
            .newCall(uploadRequest)
            .execute()
            .use { response -> readResponse(response) }

        val upload = JSONObject(uploadBody)
        val hash = upload.optString("hash")
        require(hash.matches(Regex("^[a-fA-F0-9]{32,64}$"))) { "MobSF não retornou um hash de arquivo válido" }
        val uploadedName = upload.optString("file_name").ifBlank { name }
        val scanData = "hash=${encode(hash)}&scan_type=apk&file_name=${encode(uploadedName)}"
        val scanResponse = request("$base/api/v1/scan", "POST", "Authorization", apiKey, "application/x-www-form-urlencoded", scanData.toByteArray())
        val scanJson = JSONObject(scanResponse)
        require(!scanJson.has("error")) { "MobSF: ${scanJson.optString("error")}" }
        val reportData = "hash=${encode(hash)}"
        val reportText = request("$base/api/v1/report_json", "POST", "Authorization", apiKey, "application/x-www-form-urlencoded", reportData.toByteArray())
        val report = JSONObject(reportText)
        require(!report.has("error")) { "MobSF: ${report.optString("error")}" }
        val findings = parseMobSfReport(report, hash)
        MobSfResult(findings, "MobSF concluiu a análise estática: ${findings.size} indicador(es) importado(s). Hash: $hash", hash)
    }

    private fun parseMobSfReport(report: JSONObject, hash: String): List<Finding> {
        val out = mutableListOf<Finding>()
        val categories = listOf("code_analysis", "manifest_analysis", "network_security", "certificate_analysis", "file_analysis")
        for (category in categories) {
            val obj = report.optJSONObject(category) ?: continue
            val keys = obj.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                val value = obj.opt(key)
                val records = when (value) {
                    is JSONArray -> (0 until value.length()).mapNotNull { value.optJSONObject(it) }
                    is JSONObject -> listOf(value)
                    else -> emptyList()
                }
                records.forEach { item ->
                    val title = item.optString("title").ifBlank { item.optString("name").ifBlank { key } }
                    val severityRaw = item.optString("severity", "INFO").uppercase()
                    val severity = when (severityRaw) { "CRITICAL", "HIGH" -> "HIGH"; "WARNING", "MEDIUM" -> "MEDIUM"; "LOW" -> "LOW"; else -> "INFO" }
                    val detail = listOf(item.optString("description"), item.optString("metadata"), item.optString("file_path"), item.optString("code")).filter { it.isNotBlank() }.joinToString("\n").take(4000)
                    out += Finding(target = "APK MobSF ($hash)", title = title.take(240), category = "MobSF • $category", severity = severity,
                        confidence = "Resultado automatizado MobSF; confirmar manualmente", evidence = detail.ifBlank { item.toString().take(2000) },
                        recommendedTool = "MobSF / revisão manual", remediation = item.optString("recommendation").ifBlank { "Consulte o relatório MobSF e valide o contexto." }.take(3000))
                }
            }
        }
        return out.distinctBy { it.category + it.title + it.evidence }.take(300)
    }

    private fun validateBase(baseUrl: String): String =
        PluginHttpClient.validateBase(baseUrl)

    private fun request(
        url: String,
        method: String,
        header: String? = null,
        headerValue: String? = null,
        contentType: String? = null,
        body: ByteArray? = null
    ): String {
        val parsedUrl = URL(url)
        val requestBody = body?.toRequestBody(
            contentType?.toMediaType()
        )

        val builder = Request.Builder()
            .url(url)
            .header("Accept", "application/json")

        if (header != null && headerValue != null) {
            builder.header(header, headerValue)
        }

        if (contentType != null) {
            builder.header("Content-Type", contentType)
        }

        builder.method(method, requestBody)

        val request = builder.build()

        return PluginHttpClient.clientFor(parsedUrl)
            .newCall(request)
            .execute()
            .use { response ->
                readResponse(response)
            }
    }

    private fun readResponse(response: okhttp3.Response): String {
        val output = java.io.ByteArrayOutputStream()
        val input = response.body?.byteStream()

        if (input != null) {
            input.use {
                val buffer = ByteArray(8192)
                var total = 0

                while (true) {
                    val count = it.read(buffer)
                    if (count < 0) break

                    total += count
                    require(total <= 2_000_000) {
                        "Resposta do serviço excede 2 MB."
                    }

                    output.write(buffer, 0, count)
                }
            }
        }

        val body = output.toString("UTF-8")

        require(response.isSuccessful) {
            "Servidor respondeu HTTP ${response.code}: ${body.take(500)}"
        }

        return body
    }

    private fun queryDisplayName(context: Context, uri: Uri): String = context.contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
        if (c.moveToFirst()) c.getString(0).orEmpty() else "selected.apk"
    } ?: "selected.apk"

    private fun encode(value: String): String = URLEncoder.encode(value, "UTF-8")
}
