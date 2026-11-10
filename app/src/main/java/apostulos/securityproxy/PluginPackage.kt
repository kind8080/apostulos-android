package apostulos.securityproxy

import org.json.JSONObject

/**
 * External plugin package descriptor. It contains metadata/configuration only;
 * it cannot ship executable code, DEX, native libraries, shell commands or URLs.
 * The engine must map to an adapter already implemented and trusted by APOSTULOS.
 */
data class PluginPackage(
    val id: String,
    val name: String,
    val version: String,
    val description: String,
    val engine: String
) {
    companion object {
        private val allowedEngines = setOf("web_scan", "api_scan", "apk_static", "nvd_lookup", "dirb_discovery", "zap_remote", "mobsf_remote", "nmap_agent")
        private val idPattern = Regex("^[a-z][a-z0-9_.-]{2,47}$")

        fun parse(jsonText: String): PluginPackage {
            require(jsonText.toByteArray(Charsets.UTF_8).size <= 64 * 1024) { "Pacote excede 64 KB" }
            val root = JSONObject(jsonText)
            require(root.optString("format") == "apostulos-plugin") { "Formato de pacote inválido" }
            require(root.optInt("manifestVersion", -1) == 1) { "Versão de manifesto não suportada" }
            val id = root.optString("id").trim()
            val name = root.optString("name").trim()
            val version = root.optString("version").trim()
            val description = root.optString("description").trim()
            val engine = root.optString("engine").trim()
            require(idPattern.matches(id)) { "ID inválido. Use letras minúsculas, números, ponto, hífen ou sublinhado" }
            require(name.isNotBlank() && name.length <= 60) { "Nome ausente ou muito longo" }
            require(version.matches(Regex("^[0-9]+\\.[0-9]+\\.[0-9]+([+-][A-Za-z0-9.-]+)?$"))) { "Versão deve seguir SemVer básico" }
            require(description.isNotBlank() && description.length <= 300) { "Descrição ausente ou muito longa" }
            require(engine in allowedEngines) { "Mecanismo não permitido: este pacote só pode usar adaptadores internos aprovados" }
            return PluginPackage(id, name, version, description, engine)
        }
    }
}
