package apostulos.securityproxy

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import java.net.HttpURLConnection
import java.net.URL

data class CatalogPlugin(
    val id: String,
    val name: String,
    val description: String,
    val engine: String,
    val version: String,
    val officialUrl: String
)

object PluginCatalogRepository {

    suspend fun fetchPlugins(): List<CatalogPlugin> = withContext(Dispatchers.IO) {
        val baseUrl = BuildConfig.SUPABASE_URL.trimEnd('/')
        val apiKey = BuildConfig.SUPABASE_PUBLISHABLE_KEY

        require(baseUrl.isNotBlank()) {
            "SUPABASE_URL não foi configurada no GitHub Actions."
        }
        require(apiKey.isNotBlank()) {
            "SUPABASE_PUBLISHABLE_KEY não foi configurada no GitHub Actions."
        }

        val endpoint = "$baseUrl/rest/v1/plugin_catalog" +
            "?select=id,name,description,engine,version,official_url" +
            "&published=eq.true&order=name.asc"

        val connection = URL(endpoint).openConnection() as HttpURLConnection

        try {
            connection.requestMethod = "GET"
            connection.connectTimeout = 15000
            connection.readTimeout = 15000
            connection.setRequestProperty("apikey", apiKey)
            connection.setRequestProperty("Accept", "application/json")

            val code = connection.responseCode
            val stream = if (code in 200..299) {
                connection.inputStream
            } else {
                connection.errorStream
            }

            val body = stream?.bufferedReader()?.use { it.readText() }.orEmpty()

            if (code !in 200..299) {
                throw IllegalStateException("Supabase respondeu HTTP $code: $body")
            }

            val json = JSONArray(body)
            buildList {
                for (i in 0 until json.length()) {
                    val item = json.getJSONObject(i)
                    add(
                        CatalogPlugin(
                            id = item.optString("id"),
                            name = item.optString("name"),
                            description = item.optString("description"),
                            engine = item.optString("engine"),
                            version = item.optString("version"),
                            officialUrl = item.optString("official_url")
                        )
                    )
                }
            }
        } finally {
            connection.disconnect()
        }
    }
}
