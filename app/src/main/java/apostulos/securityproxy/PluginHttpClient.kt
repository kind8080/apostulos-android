package apostulos.securityproxy

import okhttp3.Dns
import okhttp3.OkHttpClient
import java.net.Proxy
import java.net.URL
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit

object PluginHttpClient {

    fun validateBase(baseUrl: String): String {
        val clean = baseUrl.trim().trimEnd('/')
        val url = try {
            URL(clean)
        } catch (_: Exception) {
            throw IllegalArgumentException("URL do serviço inválida.")
        }

        val host = normalizeHost(url.host)

        require(url.protocol == "https" || url.protocol == "http") {
            "Somente HTTP e HTTPS são permitidos."
        }

        require(url.userInfo.isNullOrBlank() && host.isNotBlank()) {
            "Credenciais ou host inválido."
        }

        require(url.query.isNullOrBlank() && url.ref.isNullOrBlank()) {
            "Informe a URL base sem query ou fragmento."
        }

        val local = isLocalHost(host)

        require(url.protocol == "https" || local) {
            "HTTP só é permitido para localhost ou loopback."
        }

        if (local) {
            require(isLoopbackHost(host)) {
                "Serviço local deve usar endereço loopback."
            }
        }

        return clean
    }

    fun clientFor(url: URL): OkHttpClient {
        validateBase(url.origin)

        val host = normalizeHost(url.host)
        val local = isLocalHost(host)

        val safeDns = Dns { hostname ->
            val normalized = normalizeHost(hostname)

            if (normalized != host) {
                throw UnknownHostException(
                    "Resolução de hostname diferente do serviço bloqueada."
                )
            }

            val addresses = try {
                Dns.SYSTEM.lookup(hostname)
            } catch (_: Exception) {
                throw UnknownHostException(
                    "Não foi possível resolver o domínio do plugin."
                )
            }

            if (addresses.isEmpty()) {
                throw UnknownHostException("Domínio sem endereços válidos.")
            }

            if (local) {
                if (!isLoopbackHost(normalized) ||
                    addresses.any { !it.isLoopbackAddress }
                ) {
                    throw UnknownHostException(
                        "Destino local fora do loopback bloqueado."
                    )
                }
            } else {
                if (addresses.any {
                        apostulos.securityproxy.scan.NetworkTargetValidator
                            .isNonPublic(it)
                    }
                ) {
                    throw UnknownHostException(
                        "Destino privado ou reservado bloqueado."
                    )
                }
            }

            addresses
        }

        return OkHttpClient.Builder()
            .dns(safeDns)
            .proxy(Proxy.NO_PROXY)
            .followRedirects(false)
            .followSslRedirects(false)
            .retryOnConnectionFailure(false)
            .connectTimeout(20, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .writeTimeout(60, TimeUnit.SECONDS)
            .callTimeout(5, TimeUnit.MINUTES)
            .build()
    }

    private fun normalizeHost(host: String): String =
        host.removePrefix("[")
            .removeSuffix("]")
            .trim()
            .lowercase()

    private fun isLocalHost(host: String): Boolean =
        host == "localhost" || isLoopbackHost(host)

    private fun isLoopbackHost(host: String): Boolean {
        if (host == "localhost") return true

        val ipv4Literal = host.matches(
            Regex("""(?:[0-9]{1,3}\.){3}[0-9]{1,3}""")
        )

        if (ipv4Literal) {
            val octets = host.split(".").map { it.toIntOrNull() ?: return false }
            if (octets.any { it !in 0..255 }) return false
            return octets[0] == 127
        }

        return host == "::1" || host == "0:0:0:0:0:0:0:1"
    }
    private val URL.origin: String
        get() {
            val portPart = if (port == -1) "" else ":$port"
            return "$protocol://$host$portPart"
        }
}
