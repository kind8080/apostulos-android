package apostulos.securityproxy.scan

import okhttp3.Dns
import okhttp3.OkHttpClient
import java.net.Proxy
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit

object SafeHttpClient {

    private val safeDns = Dns { hostname ->
        val addresses = try {
            Dns.SYSTEM.lookup(hostname)
        } catch (_: Exception) {
            throw UnknownHostException("Não foi possível resolver o domínio.")
        }

        if (addresses.isEmpty() || addresses.any {
                NetworkTargetValidator.isNonPublic(it)
            }
        ) {
            throw UnknownHostException(
                "Destino privado, local ou reservado bloqueado."
            )
        }

        addresses
    }

    val client: OkHttpClient = OkHttpClient.Builder()
        .dns(safeDns)
        .proxy(Proxy.NO_PROXY)
        .followRedirects(false)
        .followSslRedirects(false)
        .retryOnConnectionFailure(false)
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .writeTimeout(10, TimeUnit.SECONDS)
        .callTimeout(15, TimeUnit.SECONDS)
        .build()
}
