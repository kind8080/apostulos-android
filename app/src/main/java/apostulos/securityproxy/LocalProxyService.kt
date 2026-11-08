package apostulos.securityproxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat

class LocalProxyService : Service() {
    private var server: LocalHttpProxyServer? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                server?.stop()
                server = null
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                startForeground(NOTIFICATION_ID, notification())
                if (server == null) {
                    server = LocalHttpProxyServer(PORT) { running ->
                        getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                            .putBoolean(KEY_PROXY_RUNNING, running).apply()
                    }.also { it.start() }
                }
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        server?.stop()
        server = null
        getSharedPreferences(PREFS, MODE_PRIVATE).edit().putBoolean(KEY_PROXY_RUNNING, false).apply()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, "APOSTULOS Proxy", NotificationManager.IMPORTANCE_LOW)
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun notification(): Notification = NotificationCompat.Builder(this, CHANNEL_ID)
        .setContentTitle("APOSTULOS — Proxy HTTP")
        .setContentText("Proxy local ativo em 127.0.0.1:$PORT")
        .setSmallIcon(android.R.drawable.stat_sys_upload_done)
        .setOngoing(true)
        .build()

    companion object {
        const val ACTION_START = "apostulos.action.START_PROXY"
        const val ACTION_STOP = "apostulos.action.STOP_PROXY"
        const val PORT = 8888
        const val PREFS = "apostulos_state"
        const val KEY_PROXY_RUNNING = "proxy_running"
        private const val CHANNEL_ID = "apostulos_proxy"
        private const val NOTIFICATION_ID = 8088
    }
}
