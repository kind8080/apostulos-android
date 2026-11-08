package apostulos.securityproxy

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {
    private val accounts = mapOf(
        "seteowl" to "admin/apostulos",
        "kind" to "admin/apostulos",
        "the_symon0" to "admin/apostulos"
    )
    private lateinit var content: LinearLayout
    private var username: String = ""
    private var vpnAuthorized = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        showLogin()
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun baseColumn(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(20), dp(20), dp(20), dp(28))
        setBackgroundColor(0xFF101014.toInt())
    }

    private fun label(text: String, size: Float = 15f, color: Int = 0xFFEAEAEA.toInt()) =
        TextView(this).apply { this.text = text; textSize = size; setTextColor(color) }

    private fun addButton(parent: LinearLayout, text: String, action: () -> Unit) {
        parent.addView(Button(this).apply { this.text = text; setOnClickListener { action() } },
            LinearLayout.LayoutParams(-1, dp(50)).apply { topMargin = dp(8) })
    }

    private fun showLogin() {
        val root = baseColumn().apply { gravity = Gravity.CENTER }
        root.addView(label("APOSTULOS", 30f, 0xFFD4AF37.toInt()).apply { gravity = Gravity.CENTER })
        root.addView(label("Security Proxy • Acesso local").apply { gravity = Gravity.CENTER })
        val user = EditText(this).apply { hint = "Usuário"; setSingleLine(); setTextColor(-1); setHintTextColor(0xFF999999.toInt()) }
        val pass = EditText(this).apply { hint = "Senha"; inputType = 129; setSingleLine(); setTextColor(-1); setHintTextColor(0xFF999999.toInt()) }
        listOf(user, pass).forEach { root.addView(it, LinearLayout.LayoutParams(-1, dp(52)).apply { topMargin = dp(12) }) }
        addButton(root, "ENTRAR") {
            val u = user.text.toString().trim()
            if (accounts[u] == pass.text.toString()) {
                username = u
                lifecycleScope.launch {
                    log("LOGIN", "Login local: $u")
                    showDashboard()
                }
            } else Toast.makeText(this, "Usuário ou senha inválidos", Toast.LENGTH_SHORT).show()
        }
        setContentView(root)
    }

    private fun showDashboard() {
        val scroll = ScrollView(this)
        content = baseColumn()
        scroll.addView(content)
        content.addView(label("APOSTULOS", 28f, 0xFFD4AF37.toInt()))
        content.addView(label("Bem-vindo, $username"))
        section("PROXY HTTP/HTTPS")
        content.addView(label("Proxy local: 127.0.0.1:${LocalProxyService.PORT}\nEscuta somente no próprio dispositivo. CONNECT para HTTPS e HTTP em modo forward."))
        val running = getSharedPreferences(LocalProxyService.PREFS, MODE_PRIVATE)
            .getBoolean(LocalProxyService.KEY_PROXY_RUNNING, false)
        val proxyStatus = label(if (running) "Status: ATIVO" else "Status: PARADO", 16f,
            if (running) 0xFF55CC88.toInt() else 0xFFFFAA55.toInt())
        content.addView(proxyStatus)
        addButton(content, "INICIAR PROXY") {
            val intent = Intent(this, LocalProxyService::class.java).setAction(LocalProxyService.ACTION_START)
            ContextCompat.startForegroundService(this, intent)
            proxyStatus.text = "Status: INICIANDO — 127.0.0.1:${LocalProxyService.PORT}"
            logAsync("PROXY", "Solicitada inicialização do proxy HTTP local")
        }
        addButton(content, "PARAR PROXY") {
            startService(Intent(this, LocalProxyService::class.java).setAction(LocalProxyService.ACTION_STOP))
            proxyStatus.text = "Status: PARADO"
            logAsync("PROXY", "Solicitada parada do proxy HTTP local")
        }
        section("VPN LOCAL ANDROID")
        val vpnStatus = label(if (vpnAuthorized) "Autorização VPN: concedida; encaminhamento ainda não ativado" else "Autorização VPN: não verificada", 14f)
        content.addView(vpnStatus)
        addButton(content, "AUTORIZAR VPN DO ANDROID") {
            val prepareIntent = VpnService.prepare(this)
            if (prepareIntent == null) {
                vpnAuthorized = true
                vpnStatus.text = "Autorização VPN: concedida. Motor de encaminhamento ainda precisa ser integrado."
            } else startActivityForResult(prepareIntent, VPN_REQUEST)
        }
        section("DIAGNÓSTICO E REGISTROS")
        content.addView(label("O proxy HTTP é independente da VPN. A VPN não será ativada nem desviará tráfego até a integração de um motor de tunelamento testado." , 13f, 0xFFBBBBBB.toInt()))
        addButton(content, "ATUALIZAR REGISTROS") { loadLogs() }
        addButton(content, "SAIR") { showLogin() }
        setContentView(scroll)
    }

    private fun section(title: String) {
        content.addView(TextView(this).apply {
            text = title; textSize = 17f; setTextColor(0xFFD4AF37.toInt())
            setPadding(0, dp(22), 0, dp(6))
        })
    }

    private fun logAsync(category: String, message: String) {
        lifecycleScope.launch { log(category, message) }
    }

    private suspend fun log(category: String, message: String) = withContext(Dispatchers.IO) {
        AppDatabase.get(this@MainActivity).auditLogDao().insert(
            AuditLog(createdAt = System.currentTimeMillis(), category = category, message = message)
        )
    }

    private fun loadLogs() {
        lifecycleScope.launch {
            val entries = withContext(Dispatchers.IO) { AppDatabase.get(this@MainActivity).auditLogDao().latest() }
            val report = entries.joinToString("\n") { "${java.text.DateFormat.getDateTimeInstance().format(java.util.Date(it.createdAt))} • ${it.category}: ${it.message}" }
            content.addView(TextView(this@MainActivity).apply {
                text = if (report.isBlank()) "Nenhum registro." else report
                textSize = 12f; setTextColor(0xFFCCCCCC.toInt()); setPadding(0, dp(10), 0, dp(10))
            })
        }
    }

    @Deprecated("Deprecated in Android API; retained for compatibility with minSdk 23")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST) {
            vpnAuthorized = resultCode == Activity.RESULT_OK
            if (::content.isInitialized && vpnAuthorized) {
                Toast.makeText(this, "Permissão VPN concedida. O motor de tunelamento ainda não foi ativado.", Toast.LENGTH_LONG).show()
                logAsync("VPN", "Usuário concedeu autorização VPN do Android")
                showDashboard()
            } else if (!vpnAuthorized) Toast.makeText(this, "Autorização VPN não concedida", Toast.LENGTH_SHORT).show()
        }
    }

    companion object { private const val VPN_REQUEST = 404 }
}
