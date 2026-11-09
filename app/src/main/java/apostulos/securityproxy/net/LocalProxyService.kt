package apostulos.securityproxy.net

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import apostulos.securityproxy.data.AppDatabase
import apostulos.securityproxy.data.AuditLog
import apostulos.securityproxy.data.Finding
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.cancel

class LocalProxyService : Service() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var proxy: LocalHttpProxyServer? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
        startForeground(NOTIFICATION_ID, notification("Preparando proxy local"))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                proxy?.stop()
                proxy = null
                isActive = false
                getSharedPreferences("apostulos_state", MODE_PRIVATE).edit().putBoolean("proxy_running", false).apply()
                log("Proxy", "Proxy parado pelo usuário")
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            else -> {
                if (proxy?.isRunning() != true) {
                    proxy = LocalHttpProxyServer(PORT) { message ->
                        log("Proxy", message)
                        if (message.startsWith("CLEAR_HTTP ")) {
                            serviceScope.launch {
                                runCatching {
                                    val db = AppDatabase.get(applicationContext)
                                    val reference = db.vulnerabilityDao().search("Insecure Communication").firstOrNull()
                                    val target = message.removePrefix("CLEAR_HTTP ").substringBefore(" [query omitida]")
                                    val title = "Comunicação HTTP sem criptografia observada pelo proxy"
                                    val recent = db.findingDao().countRecent(title, target, System.currentTimeMillis() - 24L * 60L * 60L * 1000L)
                                    if (recent == 0) db.findingDao().add(Finding(
                                        target = target,
                                        title = title,
                                        category = "Rede / Web",
                                        severity = "MEDIUM",
                                        confidence = "Observado no tráfego encaminhado",
                                        evidence = "O proxy recebeu uma requisição HTTP sem TLS. O conteúdo pode trafegar sem criptografia; parâmetros de consulta foram omitidos dos registros.",
                                        recommendedTool = "Wireshark / OWASP ZAP",
                                        remediation = "Use HTTPS com TLS válido em todas as rotas e evite enviar credenciais ou dados sensíveis por HTTP.",
                                        referenceUrl = reference?.referenceUrl ?: "https://mas.owasp.org/MASTG/"
                                    ))
                                }
                            }
                        }
                        updateNotification(message)
                    }
                    isActive = proxy?.start() == true
                    getSharedPreferences("apostulos_state", MODE_PRIVATE).edit().putBoolean("proxy_running", isActive).apply()
                    if (!isActive) stopSelf()
                }
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        proxy?.stop()
        proxy = null
        isActive = false
        getSharedPreferences("apostulos_state", MODE_PRIVATE).edit().putBoolean("proxy_running", false).apply()
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun log(category: String, message: String) {
        serviceScope.launch {
            runCatching { AppDatabase.get(applicationContext).auditLogDao().add(AuditLog(category = category, message = message)) }
        }
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, "APOSTULOS Proxy", NotificationManager.IMPORTANCE_LOW)
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun notification(text: String): Notification = NotificationCompat.Builder(this, CHANNEL_ID)
        .setSmallIcon(android.R.drawable.stat_sys_download_done)
        .setContentTitle("APOSTULOS • Proxy HTTP")
        .setContentText(text.take(100))
        .setOngoing(true)
        .build()

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification(text))
    }

    companion object {
        @Volatile var isActive: Boolean = false
        const val PORT = 8888
        const val ACTION_START = "apostulos.action.START_PROXY"
        const val ACTION_STOP = "apostulos.action.STOP_PROXY"
        private const val CHANNEL_ID = "apostulos_proxy"
        private const val NOTIFICATION_ID = 8888

        fun start(context: Context) {
            val intent = Intent(context, LocalProxyService::class.java).setAction(ACTION_START)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(intent) else context.startService(intent)
        }
        fun stop(context: Context) {
            context.startService(Intent(context, LocalProxyService::class.java).setAction(ACTION_STOP))
        }
    }
}
