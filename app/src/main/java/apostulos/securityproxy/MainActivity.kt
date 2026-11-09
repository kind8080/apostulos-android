package apostulos.securityproxy

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.HorizontalScrollView
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import apostulos.securityproxy.data.AppDatabase
import apostulos.securityproxy.data.AuditLog
import apostulos.securityproxy.data.Finding
import apostulos.securityproxy.data.ScanRecord
import apostulos.securityproxy.data.VulnerabilitySeed
import apostulos.securityproxy.net.LocalProxyService
import apostulos.securityproxy.scan.NvdRepository
import apostulos.securityproxy.scan.PentestScanner
import apostulos.securityproxy.security.LocalAuth
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : AppCompatActivity() {
    private lateinit var db: AppDatabase
    private lateinit var apkPicker: ActivityResultLauncher<Array<String>>
    private lateinit var pageBody: LinearLayout
    private var databaseResults: LinearLayout? = null
    private var currentPage = Page.HOME
    private var loggedUser = ""

    private enum class Page(val label: String) {
        HOME("Início"), PROXY("Proxy"), VPN("VPN"), DATABASE("Banco"), WEB("Web"), ANDROID("Android"), API("APIs"), TOOLS("Ferramentas"), FINDINGS("Falhas"), REPORTS("Relatórios"), SETTINGS("Ajustes")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        db = AppDatabase.get(this)
        getSharedPreferences("apostulos_state", MODE_PRIVATE).edit().putBoolean("proxy_running", false).apply()
        apkPicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) runApkAnalysis(uri)
        }
        lifecycleScope.launch(Dispatchers.IO) { runCatching { VulnerabilitySeed.install(db) } }
        showLogin()
    }

    private fun showLogin() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(dp(28), dp(28), dp(28), dp(28))
            setBackgroundColor(BG)
        }
        val logo = TextView(this).apply {
            text = "APOSTULOS"
            textSize = 32f
            setTextColor(GOLD)
            typeface = Typeface.create("sans-serif-black", Typeface.BOLD)
            gravity = Gravity.CENTER
        }
        root.addView(logo, matchWrap())
        val subtitle = label("SECURITY • WEB • ANDROID • API", 12f, MUTED).apply { gravity = Gravity.CENTER }
        root.addView(subtitle, matchWrap())
        val panel = card(root)
        panel.addView(label("Acesso ao painel", 20f, WHITE, true), matchWrap())
        panel.addView(label("Entre com uma das contas autorizadas.", 13f, MUTED), matchWrap())
        val user = field("Usuário")
        val pass = field("Senha").apply { inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD }
        panel.addView(user, matchWidth())
        panel.addView(pass, matchWidth())
        val login = actionButton("ENTRAR") {
            val u = user.text.toString().trim()
            val p = pass.text.toString()
            if (LocalAuth.authenticate(u, p)) {
                loggedUser = u
                getSharedPreferences("apostulos_state", MODE_PRIVATE).edit().putString("user", u).apply()
                lifecycleScope.launch(Dispatchers.IO) { runCatching { db.auditLogDao().add(AuditLog(category = "Login", message = "Sessão iniciada por $u")) } }
                render(Page.HOME)
            } else toast("Usuário ou senha inválidos")
        }
        panel.addView(login, matchWidth())
        root.addView(label("Contas autorizadas: seteowl • kind • the_symon0", 12f, MUTED).apply { gravity = Gravity.CENTER }, matchWidth())
        root.addView(label("Acesso local do aplicativo. Altere as credenciais antes de distribuir uma versão pública.", 11f, MUTED).apply { gravity = Gravity.CENTER }, matchWidth())
        setContentView(root)
    }

    private fun render(page: Page) {
        currentPage = page
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(BG) }
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(18), dp(18), dp(10))
            setBackgroundColor(BG)
        }
        val title = TextView(this).apply {
            text = "APOSTULOS"
            textSize = 23f
            setTextColor(GOLD)
            typeface = Typeface.create("sans-serif-black", Typeface.BOLD)
        }
        header.addView(title, matchWrap())
        header.addView(label("PENTEST WORKSPACE  /  ${page.label.uppercase(Locale.ROOT)}", 10f, MUTED), matchWrap())
        root.addView(header, matchWidth())

        val navScroll = HorizontalScrollView(this).apply { isHorizontalScrollBarEnabled = false }
        val nav = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(dp(12), dp(4), dp(12), dp(10)) }
        Page.values().forEach { item ->
            val button = TextView(this).apply {
                text = item.label
                textSize = 12f
                gravity = Gravity.CENTER
                setPadding(dp(13), dp(10), dp(13), dp(10))
                setTextColor(if (item == page) BG else WHITE)
                background = rounded(if (item == page) GOLD else PANEL, 24)
                setOnClickListener { render(item) }
            }
            val params = LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, dp(38)).apply { marginEnd = dp(7) }
            nav.addView(button, params)
        }
        navScroll.addView(nav)
        root.addView(navScroll, matchWidth())
        val scroll = ScrollView(this).apply { setFillViewport(true) }
        pageBody = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(8), dp(16), dp(28))
        }
        scroll.addView(pageBody)
        root.addView(scroll, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        setContentView(root)

        when (page) {
            Page.HOME -> showHome()
            Page.PROXY -> showProxy()
            Page.VPN -> showVpn()
            Page.DATABASE -> showDatabase()
            Page.WEB -> showUrlScanner("Web")
            Page.API -> showUrlScanner("API")
            Page.ANDROID -> showAndroidScanner()
            Page.TOOLS -> showTools()
            Page.FINDINGS -> showFindings()
            Page.REPORTS -> showReports()
            Page.SETTINGS -> showSettings()
        }
    }

    private fun showHome() {
        pageBody.addView(label("Centro de segurança", 24f, WHITE, true), matchWrap())
        pageBody.addView(label("Análises autorizadas, evidências e recomendações em um só lugar.", 14f, MUTED), matchWrap())
        val stats = card(pageBody)
        stats.addView(label("VISÃO GERAL", 11f, GOLD, true), matchWrap())
        lifecycleScope.launch {
            val vulnerabilities = withContext(Dispatchers.IO) { db.vulnerabilityDao().count() }
            val findings = withContext(Dispatchers.IO) { db.findingDao().count() }
            val scans = withContext(Dispatchers.IO) { db.scanDao().count() }
            stats.addView(label("$vulnerabilities referências • $findings achados • $scans análises", 17f, WHITE, true), matchWrap())
        }
        sectionTitle("Módulos")
        listOf(
            Page.PROXY to "Proxy HTTP local e histórico de conexões",
            Page.VPN to "Estado da VPN gerenciada pelo Android",
            Page.DATABASE to "Base local de CVE, CWE e OWASP",
            Page.WEB to "Verificações passivas de aplicações web",
            Page.ANDROID to "Análise estática heurística de APK",
            Page.API to "Verificações iniciais de APIs",
            Page.FINDINGS to "Achados, gravidade e ferramentas recomendadas",
            Page.REPORTS to "Histórico e exportação de relatórios"
        ).forEach { (page, description) ->
            val c = card(pageBody)
            c.addView(label(page.label, 17f, GOLD, true), matchWrap())
            c.addView(label(description, 13f, MUTED), matchWrap())
            c.addView(actionButton("ABRIR ${page.label.uppercase(Locale.ROOT)}") { render(page) }, matchWidth())
        }
        pageBody.addView(label("Importante: use somente em ativos próprios ou com autorização expressa. Os resultados são indicadores e exigem validação manual.", 12f, MUTED), matchWrap())
    }

    private fun showProxy() {
        pageBody.addView(label("Proxy HTTP / HTTPS", 23f, WHITE, true), matchWrap())
        pageBody.addView(label("Servidor local em 127.0.0.1:8888. O método CONNECT encaminha o túnel TLS sem descriptografar o conteúdo.", 14f, MUTED), matchWrap())
        val state = card(pageBody)
        val running = LocalProxyService.isActive || getSharedPreferences("apostulos_state", MODE_PRIVATE).getBoolean("proxy_running", false)
        state.addView(label(if (running) "ESTADO: INICIADO" else "ESTADO: PARADO", 18f, if (running) GREEN else GOLD, true), matchWrap())
        state.addView(label("Endereço: 127.0.0.1\nPorta: ${LocalProxyService.PORT}\nTipo: HTTP forward + CONNECT", 14f, WHITE), matchWrap())
        state.addView(actionButton("INICIAR PROXY") {
            LocalProxyService.start(this)
            getSharedPreferences("apostulos_state", MODE_PRIVATE).edit().putBoolean("proxy_running", true).apply()
            toast("Solicitação enviada. Verifique se a porta 8888 está disponível.")
            pageBody.postDelayed({ render(Page.PROXY) }, 700)
        }, matchWidth())
        state.addView(actionButton("PARAR PROXY", danger = true) {
            LocalProxyService.stop(this)
            getSharedPreferences("apostulos_state", MODE_PRIVATE).edit().putBoolean("proxy_running", false).apply()
            toast("Solicitação de parada enviada")
            pageBody.postDelayed({ render(Page.PROXY) }, 400)
        }, matchWidth())
        sectionTitle("Configuração do cliente")
        pageBody.addView(label("Configure o aplicativo ou cliente de teste para usar o proxy 127.0.0.1:8888. Nem todos os aplicativos Android respeitam o proxy Wi-Fi do sistema. Para tráfego HTTPS, o proxy apenas cria o túnel CONNECT; não instala certificado nem realiza interceptação TLS.", 13f, MUTED), matchWrap())
        pageBody.addView(actionButton("COPIAR ENDEREÇO DO PROXY") {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.setPrimaryClip(ClipData.newPlainText("APOSTULOS proxy", "127.0.0.1:8888"))
            toast("Endereço copiado")
        }, matchWidth())
        sectionTitle("Registros recentes")
        lifecycleScope.launch {
            val logs = withContext(Dispatchers.IO) { db.auditLogDao().latest().filter { it.category == "Proxy" }.take(20) }
            if (logs.isEmpty()) pageBody.addView(label("Nenhuma atividade registrada ainda.", 13f, MUTED), matchWrap())
            logs.forEach { pageBody.addView(label("${date(it.createdAt)}  •  ${it.message}", 12f, WHITE), matchWrap()) }
        }
    }

    private fun showVpn() {
        pageBody.addView(label("VPN do Android", 23f, WHITE, true), matchWrap())
        val active = isVpnActive()
        val c = card(pageBody)
        c.addView(label(if (active) "VPN DETECTADA COMO ATIVA" else "NENHUMA VPN ATIVA DETECTADA", 18f, if (active) GREEN else GOLD, true), matchWrap())
        c.addView(label("O APOSTULOS consulta o estado de rede exposto pelo Android e abre as configurações do sistema. Ele não fornece servidor VPN nem cria um túnel próprio sem um perfil/provedor configurado.", 13f, MUTED), matchWrap())
        c.addView(actionButton("ABRIR CONFIGURAÇÕES DE VPN") {
            runCatching { startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) }
                .onFailure { toast("Não foi possível abrir as configurações de VPN") }
        }, matchWidth())
        c.addView(actionButton("ATUALIZAR ESTADO") { render(Page.VPN) }, matchWidth())
        pageBody.addView(label("Privacidade", 16f, GOLD, true), matchWrap())
        pageBody.addView(label("O Android não permite que um aplicativo comum leia o conteúdo de tráfego de outra VPN. Para um túnel próprio, será necessário escolher um provedor e importar uma configuração compatível (por exemplo, WireGuard). Não exibimos um falso estado de VPN ativa.", 13f, MUTED), matchWrap())
    }

    private fun showDatabase() {
        pageBody.addView(label("Banco de vulnerabilidades", 23f, WHITE, true), matchWrap())
        pageBody.addView(label("Base local inicial com referências OWASP/CWE e registros CVE importados sob demanda da NVD.", 13f, MUTED), matchWrap())
        val search = field("Pesquisar CVE, CWE ou vulnerabilidade")
        pageBody.addView(search, matchWidth())
        pageBody.addView(actionButton("PESQUISAR NA BASE LOCAL") { loadVulnerabilities(search.text.toString()) }, matchWidth())
        pageBody.addView(actionButton("CONSULTAR NVD E IMPORTAR RESULTADOS") {
            val query = search.text.toString().trim()
            if (query.isBlank()) toast("Digite um CVE ou termo de pesquisa") else {
                toast("Consultando NVD…")
                lifecycleScope.launch {
                    runCatching {
                        NvdRepository.searchAndImport(query) { items -> db.vulnerabilityDao().insertAll(items) }
                    }.onSuccess { count ->
                        db.auditLogDao().add(AuditLog(category = "Banco", message = "$count registro(s) recebido(s) da NVD para: $query"))
                        toast("Consulta concluída: $count registro(s) recebido(s)")
                        loadVulnerabilities(query)
                    }.onFailure { toast("Falha na consulta NVD: ${it.message}") }
                }
            }
        }, matchWidth())
        val results = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        databaseResults = results
        pageBody.addView(results, matchWidth())
        loadVulnerabilities("")
    }

    private fun loadVulnerabilities(query: String) {
        lifecycleScope.launch {
            val items = withContext(Dispatchers.IO) {
                if (query.isBlank()) db.vulnerabilityDao().all() else db.vulnerabilityDao().search(query)
            }
            if (currentPage != Page.DATABASE) return@launch
            val results = databaseResults ?: return@launch
            results.removeAllViews()
            results.addView(label("${items.size} registro(s)", 17f, GOLD, true), matchWrap())
            items.take(40).forEach { item ->
                val c = card(results)
                c.addView(label(item.title, 16f, WHITE, true), matchWrap())
                c.addView(label("${item.category} • ${item.severity}${item.cwe?.let { " • $it" } ?: ""}", 11f, GOLD), matchWrap())
                c.addView(label(item.description, 12f, MUTED), matchWrap())
                c.addView(label("Correção: ${item.remediation}", 12f, WHITE), matchWrap())
                c.addView(actionButton("ABRIR REFERÊNCIA") { openUrl(item.referenceUrl) }, matchWidth())
            }
            if (items.isEmpty()) results.addView(label("Nenhum registro encontrado. Consulte a NVD ou tente outro termo.", 13f, MUTED), matchWrap())
        }
    }

    private fun showUrlScanner(category: String) {
        pageBody.addView(label(if (category == "API") "Análise de APIs" else "Análise Web", 23f, WHITE, true), matchWrap())
        pageBody.addView(label("Verificações passivas de configuração e cabeçalhos HTTP. Não executa exploração, brute force ou alteração de dados.", 13f, MUTED), matchWrap())
        val target = field(if (category == "API") "https://api.exemplo.com/health" else "https://exemplo.com")
        val authorized = CheckBox(this).apply {
            text = "Tenho autorização para testar este ativo"
            setTextColor(WHITE)
            buttonTintList = ContextCompat.getColorStateList(this@MainActivity, android.R.color.holo_orange_light)
        }
        pageBody.addView(target, matchWidth())
        pageBody.addView(authorized, matchWidth())
        pageBody.addView(actionButton("INICIAR ANÁLISE ${category.uppercase(Locale.ROOT)}") {
            if (!authorized.isChecked) toast("Confirme que possui autorização para testar este ativo")
            else runUrlAnalysis(target.text.toString(), category)
        }, matchWidth())
        pageBody.addView(label("A análise verifica a resposta inicial, cabeçalhos de segurança, cookies e algumas configurações observáveis. Ausência de cabeçalho é um ponto de hardening, não confirmação automática de falha explorável.", 12f, MUTED), matchWrap())
    }

    private fun runUrlAnalysis(target: String, category: String) {
        toast("Análise iniciada…")
        lifecycleScope.launch {
            runCatching { PentestScanner.scanWeb(target, category) }
                .onSuccess { (items, summary) ->
                    val knowledge = withContext(Dispatchers.IO) { db.vulnerabilityDao().all() }
                    val correlated = items.map { finding ->
                        val match = when {
                            finding.title.contains("cookie", true) || finding.title.contains("HSTS", true) || finding.title.contains("header", true) || finding.title.contains("framing", true) -> knowledge.firstOrNull { it.title.contains("Security Misconfiguration", true) }
                            finding.title.contains("CORS", true) -> knowledge.firstOrNull { it.title.contains("Security Misconfiguration", true) }
                            else -> null
                        }
                        if (match == null) finding else finding.copy(
                            confidence = "Heurística; correlacionado com ${match.cwe ?: match.title}",
                            referenceUrl = match.referenceUrl,
                            remediation = finding.remediation + " Referência relacionada: ${match.title}. ${match.remediation}"
                        )
                    }
                    withContext(Dispatchers.IO) {
                        db.findingDao().addAll(correlated)
                        db.scanDao().add(ScanRecord(target = target, scanType = category, status = "Concluída", summary = summary))
                        db.auditLogDao().add(AuditLog(category = "Análise", message = "$category: $summary"))
                    }
                    toast("Concluído: ${correlated.size} observação(ões)")
                    render(Page.FINDINGS)
                }
                .onFailure { error ->
                    withContext(Dispatchers.IO) { db.scanDao().add(ScanRecord(target = target, scanType = category, status = "Falhou", summary = error.message ?: "Erro de conexão")) }
                    toast("Falha na análise: ${error.message}")
                }
        }
    }

    private fun showAndroidScanner() {
        pageBody.addView(label("Análise de APK Android", 23f, WHITE, true), matchWrap())
        pageBody.addView(label("Selecione um APK para uma inspeção estática heurística de manifesto e strings DEX. O arquivo é analisado localmente e não é enviado para servidores.", 13f, MUTED), matchWrap())
        pageBody.addView(actionButton("SELECIONAR APK") { apkPicker.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream")) }, matchWidth())
        pageBody.addView(label("A verificação procura indicadores como endpoints HTTP e possíveis segredos embutidos. Não substitui MobSF, revisão de código ou análise dinâmica em laboratório.", 12f, MUTED), matchWrap())
    }

    private fun runApkAnalysis(uri: Uri) {
        toast("Analisando APK localmente…")
        lifecycleScope.launch {
            runCatching { PentestScanner.scanApk(this@MainActivity, uri) }
                .onSuccess { (items, summary) ->
                    val knowledge = withContext(Dispatchers.IO) { db.vulnerabilityDao().all() }
                    val correlated = items.map { finding ->
                        val match = when {
                            finding.title.contains("HTTP", true) || finding.title.contains("tráfego", true) -> knowledge.firstOrNull { it.title.contains("Insecure Communication", true) }
                            finding.title.contains("segredo", true) -> knowledge.firstOrNull { it.title.contains("Cryptographic Failures", true) }
                            else -> knowledge.firstOrNull { it.title.contains("Improper Platform Usage", true) }
                        }
                        if (match == null) finding else finding.copy(
                            confidence = "Triagem estática; correlacionado com ${match.cwe ?: match.title}",
                            referenceUrl = match.referenceUrl,
                            remediation = finding.remediation + " Referência relacionada: ${match.title}. ${match.remediation}"
                        )
                    }
                    withContext(Dispatchers.IO) {
                        db.findingDao().addAll(correlated)
                        db.scanDao().add(ScanRecord(target = "APK importado", scanType = "Android", status = "Concluída", summary = summary))
                        db.auditLogDao().add(AuditLog(category = "Análise", message = summary))
                    }
                    toast(summary)
                    render(Page.FINDINGS)
                }
                .onFailure { toast("Erro ao analisar APK: ${it.message}") }
        }
    }

    private fun showTools() {
        pageBody.addView(label("Ferramentas recomendadas", 23f, WHITE, true), matchWrap())
        pageBody.addView(label("O APOSTULOS associa ferramentas ao tipo de achado. Instale-as somente de fontes oficiais e use-as em escopos autorizados.", 13f, MUTED), matchWrap())
        val tools = listOf(
            Triple("OWASP ZAP", "Proxy de interceptação e scanner web de código aberto.", "https://www.zaproxy.org/"),
            Triple("Burp Suite", "Plataforma de testes manuais de aplicações web e APIs.", "https://portswigger.net/burp"),
            Triple("MobSF", "Análise estática e dinâmica de aplicações Android/iOS.", "https://github.com/MobSF/Mobile-Security-Framework-MobSF"),
            Triple("JADX", "Visualização de código Java/Kotlin aproximado a partir de DEX.", "https://github.com/skylot/jadx"),
            Triple("Nmap", "Descoberta e auditoria de serviços em redes autorizadas.", "https://nmap.org/"),
            Triple("Wireshark", "Análise de protocolos e pacotes de rede.", "https://www.wireshark.org/"),
            Triple("OWASP MAS", "Guias e testes de segurança para aplicações móveis.", "https://mas.owasp.org/"),
            Triple("NVD / CVE", "Catálogo público de vulnerabilidades e exposições.", "https://nvd.nist.gov/")
        )
        tools.forEach { (name, description, url) ->
            val c = card(pageBody)
            c.addView(label(name, 17f, GOLD, true), matchWrap())
            c.addView(label(description, 13f, MUTED), matchWrap())
            c.addView(actionButton("SITE OFICIAL") { openUrl(url) }, matchWidth())
        }
    }

    private fun showFindings() {
        pageBody.addView(label("Falhas e observações", 23f, WHITE, true), matchWrap())
        pageBody.addView(label("Resultados produzidos pelas análises e associados a recomendações de validação e correção.", 13f, MUTED), matchWrap())
        lifecycleScope.launch {
            val items = withContext(Dispatchers.IO) { db.findingDao().all() }
            if (items.isEmpty()) pageBody.addView(label("Nenhum achado registrado. Execute uma análise autorizada para começar.", 13f, MUTED), matchWrap())
            items.forEach { item ->
                val c = card(pageBody)
                c.addView(label(item.title, 16f, WHITE, true), matchWrap())
                c.addView(label("${item.severity} • ${item.category} • ${item.status}", 11f, severityColor(item.severity), true), matchWrap())
                c.addView(label("Alvo: ${item.target}", 11f, MUTED), matchWrap())
                c.addView(label("Confiança: ${item.confidence}\nEvidência: ${item.evidence}", 12f, WHITE), matchWrap())
                c.addView(label("Ferramenta recomendada: ${item.recommendedTool}", 13f, GOLD, true), matchWrap())
                c.addView(label("Correção: ${item.remediation}", 12f, MUTED), matchWrap())
                val row = LinearLayout(this@MainActivity).apply { orientation = LinearLayout.HORIZONTAL }
                row.addView(actionButton("MARCAR CORRIGIDA") {
                    lifecycleScope.launch(Dispatchers.IO) { db.findingDao().updateStatus(item.id, "Corrigida") }
                    toast("Status atualizado")
                    render(Page.FINDINGS)
                }, LinearLayout.LayoutParams(0, dp(44), 1f))
                row.addView(actionButton("REFERÊNCIA") { if (item.referenceUrl.isNotBlank()) openUrl(item.referenceUrl) }, LinearLayout.LayoutParams(0, dp(44), 1f))
                c.addView(row, matchWidth())
            }
        }
    }

    private fun showReports() {
        pageBody.addView(label("Relatórios e histórico", 23f, WHITE, true), matchWrap())
        pageBody.addView(actionButton("EXPORTAR ACHADOS") {
            lifecycleScope.launch {
                val findings = withContext(Dispatchers.IO) { db.findingDao().all() }
                val report = buildString {
                    appendLine("APOSTULOS — RELATÓRIO DE ANÁLISE")
                    appendLine("Gerado em: ${date(System.currentTimeMillis())}")
                    appendLine("Usuário: $loggedUser")
                    appendLine("=".repeat(48))
                    findings.forEachIndexed { index, f ->
                        appendLine("${index + 1}. ${f.title}")
                        appendLine("Alvo: ${f.target}")
                        appendLine("Categoria/Gravidade: ${f.category} / ${f.severity}")
                        appendLine("Evidência: ${f.evidence}")
                        appendLine("Ferramenta: ${f.recommendedTool}")
                        appendLine("Correção: ${f.remediation}")
                        appendLine("Status: ${f.status}")
                        appendLine("-")
                    }
                    if (findings.isEmpty()) appendLine("Nenhum achado registrado.")
                }
                val send = Intent(Intent.ACTION_SEND).apply { type = "text/plain"; putExtra(Intent.EXTRA_SUBJECT, "Relatório APOSTULOS"); putExtra(Intent.EXTRA_TEXT, report) }
                startActivity(Intent.createChooser(send, "Compartilhar relatório"))
            }
        }, matchWidth())
        sectionTitle("Histórico de análises")
        lifecycleScope.launch {
            val scans = withContext(Dispatchers.IO) { db.scanDao().all() }
            if (scans.isEmpty()) pageBody.addView(label("Nenhuma análise executada.", 13f, MUTED), matchWrap())
            scans.forEach { scan ->
                val c = card(pageBody)
                c.addView(label("${scan.scanType} • ${scan.status}", 15f, GOLD, true), matchWrap())
                c.addView(label("${scan.target}\n${scan.summary}\n${date(scan.createdAt)}", 12f, WHITE), matchWrap())
            }
        }
    }

    private fun showSettings() {
        pageBody.addView(label("Configurações", 23f, WHITE, true), matchWrap())
        val c = card(pageBody)
        c.addView(label("Sessão: $loggedUser", 16f, WHITE, true), matchWrap())
        c.addView(label("APOSTULOS 2.0.0\nPackage: apostulos.securityproxy\nBanco local: apostulos.db\nProxy local: 127.0.0.1:8888", 13f, MUTED), matchWrap())
        c.addView(actionButton("SAIR DA CONTA", danger = true) {
            LocalProxyService.stop(this)
            getSharedPreferences("apostulos_state", MODE_PRIVATE).edit().remove("user").apply()
            loggedUser = ""
            showLogin()
        }, matchWidth())
        pageBody.addView(label("Segurança: a senha inicial é compartilhada entre as três contas existentes. Para distribuição real, implemente troca de senha individual, armazenamento com salt/KDF e política de recuperação. O aplicativo não envia credenciais para a internet.", 12f, MUTED), matchWrap())
    }

    private fun isVpnActive(): Boolean = runCatching {
        val manager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = manager.activeNetwork ?: return false
        manager.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }.getOrDefault(false)

    private fun loadVulnerabilityListDummy() = Unit

    private fun sectionTitle(text: String) {
        pageBody.addView(label(text, 17f, GOLD, true), matchWrap())
    }

    private fun card(parent: LinearLayout): LinearLayout {
        val view = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(15), dp(14), dp(15), dp(14))
            background = rounded(PANEL, 16)
        }
        val params = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            topMargin = dp(9); bottomMargin = dp(9)
        }
        parent.addView(view, params)
        return view
    }

    private fun label(text: String, size: Float, color: Int, bold: Boolean = false): TextView = TextView(this).apply {
        this.text = text
        textSize = size
        setTextColor(color)
        if (bold) typeface = Typeface.create("sans-serif", Typeface.BOLD)
        setPadding(0, dp(4), 0, dp(4))
    }

    private fun field(hintText: String): EditText = EditText(this).apply {
        hint = hintText
        setHintTextColor(MUTED)
        setTextColor(WHITE)
        textSize = 15f
        setSingleLine(true)
        setPadding(dp(12), dp(9), dp(12), dp(9))
        background = rounded(INPUT, 10)
        val p = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(52)).apply { topMargin = dp(8); bottomMargin = dp(8) }
        layoutParams = p
    }

    private fun actionButton(text: String, danger: Boolean = false, onClick: () -> Unit): Button = Button(this).apply {
        this.text = text
        textSize = 12f
        isAllCaps = false
        setTextColor(if (danger) WHITE else BG)
        background = rounded(if (danger) RED else GOLD, 12)
        setOnClickListener { onClick() }
        val p = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(46)).apply { topMargin = dp(5); bottomMargin = dp(5) }
        layoutParams = p
    }

    private fun rounded(color: Int, radius: Int): GradientDrawable = GradientDrawable().apply {
        setColor(color)
        cornerRadius = dp(radius).toFloat()
    }

    private fun matchWidth() = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
    private fun matchWrap() = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    private fun date(time: Long): String = SimpleDateFormat("dd/MM/yyyy HH:mm", Locale("pt", "BR")).format(Date(time))
    private fun severityColor(severity: String): Int = when (severity.uppercase(Locale.ROOT)) {
        "CRITICAL", "HIGH" -> RED
        "MEDIUM" -> GOLD
        else -> MUTED
    }

    private fun openUrl(url: String) {
        runCatching { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
            .onFailure { toast("Não foi possível abrir o link") }
    }

    companion object {
        private const val BG = 0xFF0B0E14.toInt()
        private const val PANEL = 0xFF171D28.toInt()
        private const val INPUT = 0xFF202938.toInt()
        private const val GOLD = 0xFFD6B66E.toInt()
        private const val WHITE = 0xFFF4F6FA.toInt()
        private const val MUTED = 0xFF9AA5B5.toInt()
        private const val GREEN = 0xFF4BC28A.toInt()
        private const val RED = 0xFFD65C63.toInt()
    }
}
