package apostulos.securityproxy

data class PluginCatalogEntry(
    val id: String,
    val name: String,
    val version: String,
    val description: String,
    val engine: String,
    val requirement: String,
    val officialUrl: String
)

object PluginCatalog {
    val entries = listOf(
        PluginCatalogEntry(
            "apostulos_zap_connector", "OWASP ZAP Connector", "1.0.0",
            "Conector remoto para consultar a API de uma instância OWASP ZAP autorizada.",
            "zap_remote", "Servidor OWASP ZAP acessível pela rede e API habilitada", "https://www.zaproxy.org/docs/api/"
        ),
        PluginCatalogEntry(
            "apostulos_mobsf_connector", "MobSF Connector", "1.0.0",
            "Conector remoto para verificar disponibilidade da API MobSF e preparar análise de APK.",
            "mobsf_remote", "Servidor MobSF acessível e API key configurada", "https://github.com/MobSF/Mobile-Security-Framework-MobSF"
        ),
        PluginCatalogEntry(
            "apostulos_nmap_agent", "Nmap Agent Connector", "1.0.0",
            "Conector para um agente REST externo administrado por você que execute Nmap com escopo e limites definidos.",
            "nmap_agent", "Agente REST compatível com o contrato APOSTULOS /health", "https://nmap.org/book/man.html"
        )
    )
}
