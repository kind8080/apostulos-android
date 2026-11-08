package apostulos.securityproxy

import android.os.Bundle
import android.view.Gravity
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        showLogin()
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun showLogin() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(dp(24), dp(24), dp(24), dp(24))
            setBackgroundColor(0xFF101014.toInt())
        }
        root.addView(TextView(this).apply {
            text = "APOSTULOS"; textSize = 30f; gravity = Gravity.CENTER
            setTextColor(0xFFD4AF37.toInt())
        })
        root.addView(TextView(this).apply {
            text = "Security Proxy • Acesso local"; textSize = 14f
            gravity = Gravity.CENTER; setTextColor(0xFFCCCCCC.toInt())
        })
        val user = EditText(this).apply {
            hint = "Usuário"; setSingleLine()
            setTextColor(-1); setHintTextColor(0xFF999999.toInt())
        }
        val pass = EditText(this).apply {
            hint = "Senha"; inputType = 129; setSingleLine()
            setTextColor(-1); setHintTextColor(0xFF999999.toInt())
        }
        listOf(user, pass).forEach {
            root.addView(it, LinearLayout.LayoutParams(-1, dp(52)).apply { topMargin = dp(12) })
        }
        val button = Button(this).apply { text = "ENTRAR" }
        root.addView(button, LinearLayout.LayoutParams(-1, dp(52)).apply { topMargin = dp(20) })
        button.setOnClickListener {
            val u = user.text.toString().trim()
            val p = pass.text.toString()
            if (accounts[u] == p) {
                lifecycleScope.launch {
                    withContext(Dispatchers.IO) {
                        AppDatabase.get(this@MainActivity).auditLogDao().insert(
                            AuditLog(createdAt = System.currentTimeMillis(),
                                category = "LOGIN", message = "Login local: $u")
                        )
                    }
                    showDashboard(u)
                }
            } else Toast.makeText(this, "Usuário ou senha inválidos", Toast.LENGTH_SHORT).show()
        }
        setContentView(root)
    }

    private fun showDashboard(username: String) {
        val web = WebView(this)
        web.settings.javaScriptEnabled = false
        web.webViewClient = WebViewClient()
        val html = """
            <!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
            <style>
            body{background:#101014;color:#eee;font:16px sans-serif;padding:24px}
            h1{color:#d4af37}.card{background:#202027;padding:16px;margin:12px 0;border-radius:12px}
            small{color:#aaa}
            </style></head><body>
            <h1>APOSTULOS</h1><small>Bem-vindo, $username</small>
            <div class="card"><b>Painel de segurança</b><p>Aplicativo inicial configurado.</p></div>
            <div class="card"><b>Proxy local</b><p>Não iniciado nesta versão. Nenhuma porta está sendo escutada.</p></div>
            <div class="card"><b>Diagnóstico</b><p>Use apenas em sistemas próprios ou com autorização explícita.</p></div>
            <div class="card"><b>Registros</b><p>Eventos de login são armazenados localmente no banco Room.</p></div>
            </body></html>
        """.trimIndent()
        web.loadDataWithBaseURL(null, html, "text/html", "UTF-8", null)
        setContentView(web)
    }
}
