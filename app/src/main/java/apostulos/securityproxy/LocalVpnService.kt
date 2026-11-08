package apostulos.securityproxy

import android.net.VpnService
import android.content.Intent

/** Declares Android's VPN consent endpoint. Packet forwarding is intentionally not started yet. */
class LocalVpnService : VpnService() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_NOT_STICKY
}
