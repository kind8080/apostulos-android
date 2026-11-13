package apostulos.securityproxy.scan

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URL

object NetworkTargetValidator {

    fun validate(rawTarget: String): URL {
        val clean = rawTarget.trim()

        val url = try {
            URL(
                if (clean.startsWith("http://", true) ||
                    clean.startsWith("https://", true)
                ) clean else "https://$clean"
            )
        } catch (_: Exception) {
            throw IllegalArgumentException("URL inválida.")
        }

        require(url.protocol == "http" || url.protocol == "https") {
            "Somente HTTP e HTTPS são permitidos."
        }

        require(url.userInfo.isNullOrBlank() && url.host.isNotBlank()) {
            "Credenciais ou host inválido."
        }

        require(url.port == -1 ||
            (url.protocol == "http" && url.port == 80) ||
            (url.protocol == "https" && url.port == 443)
        ) {
            "Porta não permitida."
        }

        val addresses = try {
            InetAddress.getAllByName(url.host)
        } catch (_: Exception) {
            throw IllegalArgumentException("Não foi possível resolver o domínio.")
        }

        require(addresses.isNotEmpty() && addresses.none { isNonPublic(it) }) {
            "Destino privado, local ou reservado bloqueado."
        }

        return url
    }

    internal fun isNonPublic(address: InetAddress): Boolean {
        if (address.isAnyLocalAddress ||
            address.isLoopbackAddress ||
            address.isLinkLocalAddress ||
            address.isSiteLocalAddress ||
            address.isMulticastAddress
        ) return true

        val b = address.address.map { it.toInt() and 0xff }

        if (address is Inet4Address) {
            return b[0] == 0 ||
                b[0] == 10 ||
                b[0] == 127 ||
                b[0] >= 224 ||
                (b[0] == 100 && b[1] in 64..127) ||
                (b[0] == 169 && b[1] == 254) ||
                (b[0] == 172 && b[1] in 16..31) ||
                (b[0] == 192 && b[1] == 0 && b[2] in 0..2) ||
                (b[0] == 192 && b[1] == 88 && b[2] == 99) ||
                (b[0] == 192 && b[1] == 168) ||
                (b[0] == 198 && b[1] in 18..19) ||
                (b[0] == 198 && b[1] == 51 && b[2] == 100) ||
                (b[0] == 203 && b[1] == 0 && b[2] == 113) ||
                (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255)
        }

        if (address is Inet6Address) {
            val mappedIpv4 = b.take(10).all { it == 0 } &&
                b[10] == 255 && b[11] == 255

            if (mappedIpv4) {
                val ipv4 = InetAddress.getByAddress(address.address.copyOfRange(12, 16))
                return isNonPublic(ipv4)
            }

            val sixToFour = b[0] == 0x20 && b[1] == 0x02
            if (sixToFour) {
                val embeddedIpv4 = InetAddress.getByAddress(
                    address.address.copyOfRange(2, 6)
                )
                if (isNonPublic(embeddedIpv4)) return true
            }

            val nat64WellKnown = b.take(12) ==
                listOf(0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00)
            if (nat64WellKnown) {
                val embeddedIpv4 = InetAddress.getByAddress(
                    address.address.copyOfRange(12, 16)
                )
                if (isNonPublic(embeddedIpv4)) return true
            }

            val documentation = b[0] == 0x20 && b[1] == 0x01 &&
                b[2] == 0x0d && b[3] == 0xb8

            val discardOnly = b[0] == 0x01 && b[1] == 0x00

            return (b[0] and 0xfe) == 0xfc ||
                (b[0] == 0xfe && (b[1] and 0xc0) == 0x80) ||
                b[0] == 0xff ||
                b.all { it == 0 } ||
                (b.take(15).all { it == 0 } && b[15] == 1) ||
                documentation ||
                discardOnly ||
                sixToFour
        }

        return true
    }
}
