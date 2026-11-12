package apostulos.securityproxy.net

import apostulos.securityproxy.BuildConfig
import io.ktor.client.HttpClient
import io.ktor.client.engine.android.Android
import io.ktor.client.request.get
import io.ktor.client.request.headers
import io.ktor.client.request.url
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.isSuccess
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray

data class CloudPlugin(
    val id: String,
    val name: String,
    val version: String,
    val description: String,
    val engine: String,
    val officialUrl: String
)

object SupabasePluginRepository {

    suspend fun fetchPublishedPlugins(): List<CloudPlugin> =
        withContext(Dispatchers.IO) {

            val baseUrl = BuildConfig.SUPABASE_URL.trimEnd('/')
            val key = BuildConfig.SUPABASE_PUBLISHABLE_KEY

            require(baseUrl.startsWith("https://")) {
                "URL do Supabase inválida ou não configurada."
            }
            require(key.isNotBlank()) {
                "Chave pública do Supabase não configurada."
            }

            val client = HttpClient(Android)

            try {
                val response = client.get("$baseUrl/rest/v1/plugin_catalog") {
                    headers {
                        append("apikey", key)
                        append(HttpHeaders.Accept, "application/json")
                    }
                    url {
                        parameters.append(
                            "select",
                            "id,name,version,description,engine,official_url"
                        )
                        parameters.append("published", "eq.true")
                        parameters.append("order", "name.asc")
                    }
                }

                if (!response.status.isSuccess()) {
                    throw IllegalStateException(
                        "Supabase respondeu HTTP ${response.status.value}."
                    )
                }

                val json = JSONArray(response.bodyAsText())

                buildList {
                    for (i in 0 until json.length()) {
                        val item = json.getJSONObject(i)
                        add(
                            CloudPlugin(
                                id = item.optString("id"),
                                name = item.optString("name"),
                                version = item.optString("version"),
                                description = item.optString("description", ""),
                                engine = item.optString("engine", ""),
                                officialUrl = item.optString("official_url", "")
                            )
                        )
                    }
                }
            } finally {
                client.close()
            }
        }
}
