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
import apostulos.securityproxy.data.InstalledPlugin
import apostulos.securityproxy.data.ScanRecord
import apostulos.securityproxy.data.SourceSync
import apostulos.securityproxy.data.VulnerabilitySeed
import apostulos.securityproxy.net.LocalProxyService
import apostulos.securityproxy.scan.NvdRepository
import apostulos.securityproxy.scan.PentestScanner
import apostulos.securityproxy.scan.RiskAssessment
import apostulos.securityproxy.security.LocalAuth
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import org.json.JSONObject

class MainActivity : AppCompatActivity() {
    private lateinit var db: AppDatabase
    private lateinit var apkPicker: ActivityResultLauncher<Array<String>>
    private lateinit var pluginPackagePicker: ActivityResultLauncher<Array<String>>
    private lateinit var mobsfApkPicker: ActivityResultLauncher<Array<String>>
    private var mobsfPluginForUpload: InstalledPlugin? = null
    private lateinit var pageBody: LinearLayout
    private var databaseResults: LinearLayout? = null
    private var currentPage = Page.HOME
    private var loggedUser = ""
    private var consoleModule = "dirb"

    private enum class Page(val label: String) {
        HOME("Início"), PROXY("Proxy"), VPN("VPN"), DATABASE("Banco"), WEB("Web"), ANDROID("Android"), API("APIs"),
        CONSOLE("Console"), PLUGINS("Plugins"), TOOLS("Ferramentas"), FINDINGS("Falhas"), REPORTS("Relatórios"), SETTINGS("Ajustes")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        db = AppDatabase.get(this)
        getSharedPreferences("apostulos_state", MODE_PRIVATE).edit().putBoolean("proxy_running", false).apply()
        apkPicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) runApkAnalysis(uri)
        }
        pluginPackagePicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) importPluginPackage(uri)
        }
        mobsfApkPicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            val plugin = mobsfPluginForUpload
            mobsfPluginForUpload = null
            if (uri != null && plugin != null) runMobSfAnalysis(plugin, uri)
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
            Page.CONSOLE -> showConsole()
            Page.PLUGINS -> showPlugins()
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
            Page.CONSOLE to "Console simples para módulos de auditoria autorizada",
            Page.PLUGINS to "Ativar e desativar módulos internos",
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
            if (!pluginEnabled("nvd_lookup")) toast("Ative o módulo de consulta NVD em Plugins")
            else if (query.isBlank()) toast("Digite um CVE ou termo de pesquisa") else {
                toast("Consultando NVD…")
                lifecycleScope.launch {
                    runCatching {
                        NvdRepository.searchAndImport(query) { items -> db.vulnerabilityDao().upsertAll(items) }
                    }.onSuccess { count ->
                        val now = System.currentTimeMillis()
                        db.sourceSyncDao().save(SourceSync("NVD", now, now, count, "OK", "Consulta: $query"))
                        db.auditLogDao().add(AuditLog(category = "Banco", message = "$count registro(s) recebido(s) da NVD para: $query"))
                        toast("Consulta concluída: $count registro(s) recebido(s)")
                        loadVulnerabilities(query)
                    }.onFailure {
                        val now = System.currentTimeMillis()
                        withContext(Dispatchers.IO) { db.sourceSyncDao().save(SourceSync("NVD", now, db.sourceSyncDao().get("NVD")?.lastSuccessAt, 0, "ERRO", it.message ?: "Falha sem detalhes")) }
                        toast("Falha na consulta NVD: ${it.message}")
                    }
                }
            }
        }, matchWidth())
        pageBody.addView(actionButton("ATUALIZAR EPSS + CISA KEV") {
            toast("Atualizando inteligência de ameaças…")
            lifecycleScope.launch {
                runCatching { NvdRepository.refreshThreatIntel(db) }
                    .onSuccess { (epss, kev) ->
                        withContext(Dispatchers.IO) {
                            val now = System.currentTimeMillis()
                            db.sourceSyncDao().save(SourceSync("FIRST.org EPSS", now, now, epss, "OK", "Probabilidade estimada de exploração atualizada"))
                            db.sourceSyncDao().save(SourceSync("CISA KEV", now, now, kev, "OK", "Catálogo de vulnerabilidades conhecidamente exploradas consultado"))
                            db.auditLogDao().add(AuditLog(category = "Banco", message = "Inteligência atualizada: $epss EPSS; $kev entradas KEV processadas"))
                        }
                        toast("Atualização concluída: $epss EPSS; $kev CVE(s) locais correspondem ao KEV")
                        loadVulnerabilities(search.text.toString())
                    }
                    .onFailure {
                        withContext(Dispatchers.IO) {
                            val now = System.currentTimeMillis()
                            listOf("FIRST.org EPSS", "CISA KEV").forEach { source ->
                                db.sourceSyncDao().save(SourceSync(source, now, db.sourceSyncDao().get(source)?.lastSuccessAt, 0, "ERRO", it.message ?: "Falha sem detalhes"))
                            }
                        }
                        toast("Falha ao atualizar EPSS/CISA KEV: ${it.message}")
                    }
            }
        }, matchWidth())
        val syncStatus = label("Fontes externas: carregando estado…", 12f, MUTED)
        pageBody.addView(syncStatus, matchWrap())
        lifecycleScope.launch {
            val syncItems = withContext(Dispatchers.IO) { db.sourceSyncDao().all() }
            syncStatus.text = if (syncItems.isEmpty()) "Fontes externas: ainda não sincronizadas nesta instalação." else syncItems.joinToString("\n") { item ->
                "${item.source}: ${item.status} • ${item.recordsProcessed} registro(s) • ${item.lastSuccessAt?.let { date(it) } ?: "sem sincronização bem-sucedida"}\n${item.details}"
            }
        }
        pageBody.addView(label("CVSS representa severidade técnica (0–10). EPSS estima probabilidade de exploração. CISA KEV indica vulnerabilidades conhecidamente exploradas. Nenhum desses indicadores substitui a análise do contexto do ativo.", 12f, MUTED), matchWrap())
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
                c.addView(label("${item.category} • ${item.severity}${item.cwe?.let { " • $it" } ?: ""}", 11f, severityColor(item.severity), true), matchWrap())
                val riskDetails = buildList {
                    item.cvssScore?.let { add("CVSS ${String.format(Locale.US, "%.1f", it)}") }
                    item.epssScore?.let { add("EPSS ${String.format(Locale.US, "%.2f%%", it * 100.0)}") }
                    if (item.knownExploited) add("CISA KEV: explorada")
                    if (item.attackVector != null) add("Vetor: ${item.attackVector}")
                }
                if (riskDetails.isNotEmpty()) c.addView(label(riskDetails.joinToString(" • "), 12f, GOLD, true), matchWrap())
                val triage = RiskAssessment.assess(item.cvssScore, item.epssScore, item.knownExploited)
                c.addView(label("PRIORIDADE APOSTULOS: ${triage.priority}${triage.score?.let { " • ${it}/100" } ?: ""}", 12f, if (item.knownExploited || triage.priority == "CRÍTICO" || triage.priority == "ALTO") RED else GOLD, true), matchWrap())
                c.addView(label(triage.explanation, 10f, MUTED), matchWrap())
                if (item.cvssVector != null) c.addView(label("CVSS ${item.cvssVersion ?: "?"} vetor: ${item.cvssVector}", 10f, MUTED), matchWrap())
                if (item.affectedProducts.isNotBlank()) c.addView(label("Produtos/versões afetados (CPE):\n${item.affectedProducts.lines().take(5).joinToString("\n")}", 10f, MUTED), matchWrap())
                c.addView(label("Fonte: ${item.source} • Atualizado: ${date(item.updatedAt)}", 10f, MUTED), matchWrap())
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
            else if (!pluginEnabled(if (category == "API") "api_scan" else "web_scan")) toast("Ative este módulo em Plugins antes de executar")
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
        pageBody.addView(actionButton("SELECIONAR APK") {
            if (!pluginEnabled("apk_static")) toast("Ative o módulo Android estático em Plugins")
            else apkPicker.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream"))
        }, matchWidth())
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

    private fun pluginEnabled(id: String): Boolean =
        getSharedPreferences("apostulos_plugins", MODE_PRIVATE).getBoolean(id, true)

    private fun importPluginPackage(uri: Uri) {
        lifecycleScope.launch {
            runCatching {
                val bytes = withContext(Dispatchers.IO) {
                    contentResolver.openInputStream(uri)?.use { input ->
                        val output = java.io.ByteArrayOutputStream()
                        val buffer = ByteArray(4096)
                        while (true) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            require(output.size() + count <= 64 * 1024) { "Pacote excede 64 KB" }
                            output.write(buffer, 0, count)
                        }
                        output.toByteArray()
                    } ?: error("Não foi possível ler o pacote")
                }
                val descriptor = PluginPackage.parse(bytes.toString(Charsets.UTF_8))
                withContext(Dispatchers.IO) {
                    val existing = db.installedPluginDao().get(descriptor.id)
                    if (existing != null) {
                        require(comparePluginVersions(descriptor.version, existing.version) > 0) {
                            "A versão importada deve ser superior à versão instalada (${existing.version})."
                        }
                    }
                    db.installedPluginDao().upsert(
                        InstalledPlugin(
                            pluginId = descriptor.id,
                            name = descriptor.name,
                            version = descriptor.version,
                            description = descriptor.description,
                            engine = descriptor.engine,
                            configJson = existing?.configJson ?: "{}",
                            enabled = existing?.enabled ?: true,
                            installedAt = existing?.installedAt ?: System.currentTimeMillis()
                        )
                    )
                    db.auditLogDao().add(AuditLog(category = "Plugins", message = "Pacote ${descriptor.id} ${descriptor.version} ${if (existing == null) "instalado" else "atualizado"}"))
                }
                getSharedPreferences("apostulos_plugins", MODE_PRIVATE).edit().putBoolean(descriptor.engine, true).apply()
                toast("Plugin ${descriptor.name} instalado e adaptador ativado")
                render(Page.PLUGINS)
            }.onFailure { toast("Falha ao importar plugin: ${it.message}") }
        }
    }

    private fun showPlugins() {
        pageBody.addView(label("Central de plugins", 23f, WHITE, true), matchWrap())
        pageBody.addView(label("Instale pacotes de manifesto JSON, ative módulos, ajuste configurações e abra o adaptador correspondente. Por segurança, pacotes externos não executam código arbitrário: cada um precisa apontar para um mecanismo interno aprovado.", 13f, MUTED), matchWrap())
        pageBody.addView(actionButton("IMPORTAR PACOTE DE PLUGIN (.JSON)") {
            pluginPackagePicker.launch(arrayOf("application/json", "text/json", "text/plain"))
        }, matchWidth())
        pageBody.addView(actionButton("VER MODELO DE PACOTE") {
            val sample = """{
  "format": "apostulos-plugin",
  "manifestVersion": 1,
  "id": "web_headers_plus",
  "name": "Web Headers Plus",
  "version": "1.0.0",
  "description": "Atalho para auditoria passiva de cabeçalhos HTTP",
  "engine": "web_scan"
}"""
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.setPrimaryClip(ClipData.newPlainText("Modelo de plugin APOSTULOS", sample))
            toast("Modelo JSON copiado")
        }, matchWidth())

        pageBody.addView(label("Catálogo de conectores externos", 17f, GOLD, true), matchWrap())
        pageBody.addView(label("Os conectores exigem serviços instalados e administrados por você. O APOSTULOS não baixa nem executa binários externos.", 12f, MUTED), matchWrap())
        PluginCatalog.entries.forEach { entry ->
            val c = card(pageBody)
            c.addView(label(entry.name, 16f, WHITE, true), matchWrap())
            c.addView(label(entry.description, 12f, MUTED), matchWrap())
            c.addView(label("Requisito: ${entry.requirement}", 11f, MUTED), matchWrap())
            c.addView(actionButton("INSTALAR / ATUALIZAR CONECTOR") {
                lifecycleScope.launch {
                    runCatching {
                        withContext(Dispatchers.IO) {
                            val old = db.installedPluginDao().get(entry.id)
                            require(old == null || comparePluginVersions(entry.version, old.version) > 0) {
                                "A versão do catálogo não é mais nova que a instalada."
                            }
                            db.installedPluginDao().upsert(InstalledPlugin(
                                pluginId = entry.id, name = entry.name, version = entry.version,
                                description = entry.description, engine = entry.engine,
                                configJson = old?.configJson ?: "{}", enabled = old?.enabled ?: false,
                                installedAt = old?.installedAt ?: System.currentTimeMillis()
                            ))
                            db.auditLogDao().add(AuditLog(category = "Plugins", message = "Conector ${entry.id} ${if (old == null) "instalado" else "atualizado"}"))
                        }
                        toast("${entry.name} instalado. Configure o endpoint para conectar.")
                        render(Page.PLUGINS)
                    }.onFailure { toast("Não foi possível instalar: ${it.message}") }
                }
            }, matchWidth())
            c.addView(actionButton("DOCUMENTAÇÃO OFICIAL") { openExternalUrl(entry.officialUrl) }, matchWidth())
        }

        pageBody.addView(label("Módulos que já vêm no aplicativo", 17f, GOLD, true), matchWrap())
        val modules = listOf(
            Triple("web_scan", "Auditoria Web", "Cabeçalhos HTTP, cookies e configurações observáveis"),
            Triple("api_scan", "Auditoria de APIs", "Verificações passivas de resposta e CORS"),
            Triple("apk_static", "Análise Android", "Triagem estática de manifesto e strings DEX"),
            Triple("nvd_lookup", "NVD / CVE", "Pesquisa e importação de vulnerabilidades"),
            Triple("dirb_discovery", "Content Discovery", "Descoberta limitada de caminhos por HEAD")
        )
        modules.forEach { (id, name, description) ->
            val c = card(pageBody)
            val toggle = CheckBox(this).apply {
                text = name
                textSize = 15f
                setTextColor(GOLD)
                isChecked = pluginEnabled(id)
                setOnCheckedChangeListener { _, checked ->
                    getSharedPreferences("apostulos_plugins", MODE_PRIVATE).edit().putBoolean(id, checked).apply()
                    toast("$name ${if (checked) "ativado" else "desativado"}")
                }
            }
            c.addView(toggle, matchWidth())
            c.addView(label(description, 12f, MUTED), matchWrap())
        }

        pageBody.addView(label("Pacotes externos instalados", 17f, GOLD, true), matchWrap())
        lifecycleScope.launch {
            val installed = withContext(Dispatchers.IO) { db.installedPluginDao().all() }
            if (installed.isEmpty()) {
                pageBody.addView(label("Nenhum pacote externo instalado. Importe um manifesto JSON para adicionar um plugin compatível.", 12f, MUTED), matchWrap())
            }
            installed.forEach { plugin ->
                val c = card(pageBody)
                c.addView(label(plugin.name, 16f, WHITE, true), matchWrap())
                c.addView(label("ID: ${plugin.pluginId} • versão ${plugin.version}", 11f, MUTED), matchWrap())
                c.addView(label(plugin.description, 12f, MUTED), matchWrap())
                c.addView(label("Adaptador: ${plugin.engine} • código executado: interno do APOSTULOS", 11f, MUTED), matchWrap())
                val toggle = CheckBox(this@MainActivity).apply {
                    text = "Plugin ativado"
                    setTextColor(GOLD)
                    isChecked = plugin.enabled
                    setOnCheckedChangeListener { _, checked ->
                        getSharedPreferences("apostulos_plugins", MODE_PRIVATE).edit().putBoolean(plugin.engine, checked).apply()
                        lifecycleScope.launch(Dispatchers.IO) { db.installedPluginDao().setEnabled(plugin.pluginId, checked) }
                        toast(if (checked) "Plugin e adaptador ativados" else "Plugin e adaptador desativados")
                    }
                }
                c.addView(toggle, matchWidth())
                c.addView(actionButton("CONFIGURAR") {
                    if (plugin.engine in setOf("zap_remote", "mobsf_remote", "nmap_agent")) showConnectorConfig(plugin)
                    else showPluginConfig(plugin)
                }, matchWidth())
                if (plugin.engine in setOf("zap_remote", "mobsf_remote", "nmap_agent")) {
                    c.addView(actionButton("TESTAR CONEXÃO") { testExternalConnector(plugin) }, matchWidth())
                }
                if (plugin.engine == "zap_remote") {
                    c.addView(actionButton("IMPORTAR ALERTAS PASSIVOS DO ZAP") { importZapPassiveAlerts(plugin) }, matchWidth())
                    c.addView(label("Somente consulta alertas já existentes; não inicia active scan.", 10f, MUTED), matchWrap())
                }
                if (plugin.engine == "mobsf_remote") {
                    c.addView(actionButton("ENVIAR APK E ANALISAR NO MOBSF") {
                        if (!plugin.enabled || !pluginEnabled(plugin.engine)) toast("Ative o plugin antes de usar")
                        else { mobsfPluginForUpload = plugin; mobsfApkPicker.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream")) }
                    }, matchWidth())
                    c.addView(label("O APK escolhido será enviado ao servidor MobSF configurado. Faça isso apenas com arquivos que você tem autorização para compartilhar.", 10f, MUTED), matchWrap())
                }
                c.addView(actionButton("ABRIR MÓDULO", onClick = { openPluginEngine(plugin) }), matchWidth())
                c.addView(actionButton("REMOVER PLUGIN", danger = true) {
                    lifecycleScope.launch {
                        withContext(Dispatchers.IO) {
                            db.installedPluginDao().remove(plugin.pluginId)
                            PluginSecretStore(this@MainActivity).remove(plugin.pluginId)
                            db.auditLogDao().add(AuditLog(category = "Plugins", message = "Plugin ${plugin.pluginId} removido"))
                        }
                        toast("Plugin removido")
                        render(Page.PLUGINS)
                    }
                }, matchWidth())
            }
        }
        lifecycleScope.launch {
            val events = withContext(Dispatchers.IO) {
                db.auditLogDao().latest().filter { it.category == "Plugins" }.take(12)
            }
            pageBody.addView(label("Atividade recente dos plugins", 17f, GOLD, true), matchWrap())
            if (events.isEmpty()) {
                pageBody.addView(label("Nenhuma atividade registrada ainda.", 12f, MUTED), matchWrap())
            } else events.forEach { event ->
                pageBody.addView(label("${Date(event.createdAt)} • ${event.message}", 11f, MUTED), matchWrap())
            }
        }
    }

    private fun comparePluginVersions(left: String, right: String): Int {
        fun parts(value: String) = value.substringBefore('+').split('.').map { it.toIntOrNull() ?: 0 }
        val a = parts(left); val b = parts(right)
        for (i in 0 until maxOf(a.size, b.size)) {
            val diff = (a.getOrElse(i) { 0 }).compareTo(b.getOrElse(i) { 0 })
            if (diff != 0) return diff
        }
        return left.compareTo(right)
    }

    private fun openExternalUrl(url: String) {
        runCatching { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
            .onFailure { toast("Não foi possível abrir o link") }
    }

    private fun showConnectorConfig(plugin: InstalledPlugin) {
        val saved = runCatching { JSONObject(plugin.configJson).optString("baseUrl", "") }.getOrDefault("")
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(12), dp(20), dp(8))
        }
        val endpoint = EditText(this).apply {
            hint = "Endpoint do serviço (https://servidor:porta)"
            setSingleLine(true)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setText(saved)
        }
        layout.addView(label("Endereço base do serviço", 12f, MUTED), matchWrap())
        layout.addView(endpoint, matchWidth())
        val apiKey = EditText(this).apply {
            hint = if (plugin.engine == "nmap_agent") "Sem chave para o health check" else "API key (armazenada criptografada)"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            if (plugin.engine == "nmap_agent") isEnabled = false
        }
        layout.addView(apiKey, matchWidth())
        layout.addView(label("A chave será protegida pelo Android Keystore. Use HTTPS fora de uma rede local de laboratório.", 11f, MUTED), matchWrap())
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Conectar ${plugin.name}")
            .setView(layout)
            .setNegativeButton("Cancelar", null)
            .setNeutralButton("Salvar", null)
            .setPositiveButton("Salvar e testar", null)
            .create().also { dialog ->
                dialog.setOnShowListener {
                    dialog.getButton(androidx.appcompat.app.AlertDialog.BUTTON_NEUTRAL).setOnClickListener {
                        saveConnectorConfig(plugin, endpoint.text.toString(), apiKey.text.toString(), test = false)
                        dialog.dismiss()
                    }
                    dialog.getButton(androidx.appcompat.app.AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                        saveConnectorConfig(plugin, endpoint.text.toString(), apiKey.text.toString(), test = true)
                        dialog.dismiss()
                    }
                }
                dialog.show()
            }
    }

    private fun saveConnectorConfig(plugin: InstalledPlugin, rawUrl: String, rawSecret: String, test: Boolean) {
        lifecycleScope.launch {
            runCatching {
                val url = rawUrl.trim().trimEnd('/')
                val parsed = java.net.URL(url)
                require(parsed.protocol == "https" || (parsed.protocol == "http" && parsed.host in setOf("localhost", "127.0.0.1", "::1"))) {
                    "Use HTTPS. HTTP só é permitido para localhost."
                }
                require(parsed.userInfo.isNullOrBlank()) { "Não inclua credenciais na URL" }
                withContext(Dispatchers.IO) {
                    db.installedPluginDao().saveConfig(plugin.pluginId, JSONObject().put("baseUrl", url).toString())
                    if (rawSecret.isNotBlank()) PluginSecretStore(this@MainActivity).save(plugin.pluginId, rawSecret)
                }
                toast("Endpoint salvo")
                if (test) testExternalConnector(plugin.copy(configJson = JSONObject().put("baseUrl", url).toString()))
                else render(Page.PLUGINS)
            }.onFailure { toast("Configuração inválida: ${it.message}") }
        }
    }

    private fun testExternalConnector(plugin: InstalledPlugin) {
        lifecycleScope.launch {
            val result = runCatching {
                val baseUrl = JSONObject(plugin.configJson).optString("baseUrl", "")
                require(baseUrl.isNotBlank()) { "Configure primeiro o endpoint do serviço" }
                val secret = withContext(Dispatchers.IO) { PluginSecretStore(this@MainActivity).read(plugin.pluginId) }
                ExternalPluginConnector.test(plugin.engine, baseUrl, secret)
            }
            val message = result.getOrElse { "Falha na conexão: ${it.message}" }
            withContext(Dispatchers.IO) {
                db.auditLogDao().add(AuditLog(category = "Plugins", message = "${plugin.name}: $message"))
            }
            toast(message)
        }
    }

    private fun importZapPassiveAlerts(plugin: InstalledPlugin) {
        if (!plugin.enabled || !pluginEnabled(plugin.engine)) { toast("Ative o plugin antes de usar"); return }
        lifecycleScope.launch {
            val result = runCatching {
                val base = JSONObject(plugin.configJson).optString("baseUrl", "")
                require(base.isNotBlank()) { "Configure primeiro o endpoint do ZAP" }
                val secret = withContext(Dispatchers.IO) { PluginSecretStore(this@MainActivity).read(plugin.pluginId) }
                ExternalPluginConnector.fetchZapPassiveAlerts(base, secret)
            }
            result.onSuccess { data ->
                withContext(Dispatchers.IO) {
                    val fresh = data.findings.filter { db.findingDao().countRecent(it.title, it.target, System.currentTimeMillis() - 24L * 60L * 60L * 1000L) == 0 }
                    if (fresh.isNotEmpty()) db.findingDao().addAll(fresh)
                    db.scanDao().add(ScanRecord(target = "Instância OWASP ZAP", scanType = "ZAP passivo", status = "Concluída", summary = data.summary + " Novos: ${fresh.size}."))
                    db.auditLogDao().add(AuditLog(category = "Plugins", message = data.summary))
                }
                toast(data.summary)
                render(Page.FINDINGS)
            }.onFailure { error ->
                withContext(Dispatchers.IO) { db.auditLogDao().add(AuditLog(category = "Plugins", message = "ZAP: falha ao importar alertas: ${error.message}")) }
                toast("Falha ao consultar ZAP: ${error.message}")
            }
        }
    }

    private fun runMobSfAnalysis(plugin: InstalledPlugin, uri: Uri) {
        if (!plugin.enabled || !pluginEnabled(plugin.engine)) { toast("Ative o plugin antes de usar"); return }
        toast("Enviando APK selecionado ao MobSF…")
        lifecycleScope.launch {
            val result = runCatching {
                val base = JSONObject(plugin.configJson).optString("baseUrl", "")
                require(base.isNotBlank()) { "Configure primeiro o endpoint do MobSF" }
                val secret = withContext(Dispatchers.IO) { PluginSecretStore(this@MainActivity).read(plugin.pluginId) }.orEmpty()
                ExternalPluginConnector.analyzeApkWithMobSf(this@MainActivity, uri, base, secret)
            }
            result.onSuccess { data ->
                withContext(Dispatchers.IO) {
                    val fresh = data.findings.filter { db.findingDao().countRecent(it.title, it.target, System.currentTimeMillis() - 24L * 60L * 60L * 1000L) == 0 }
                    if (fresh.isNotEmpty()) db.findingDao().addAll(fresh)
                    db.scanDao().add(ScanRecord(target = "APK enviado ao MobSF", scanType = "MobSF estático", status = "Concluída", summary = data.summary + " Novos: ${fresh.size}."))
                    db.auditLogDao().add(AuditLog(category = "Plugins", message = data.summary))
                }
                toast(data.summary)
                render(Page.FINDINGS)
            }.onFailure { error ->
                withContext(Dispatchers.IO) { db.auditLogDao().add(AuditLog(category = "Plugins", message = "MobSF: falha na análise: ${error.message}")) }
                toast("Falha na análise MobSF: ${error.message}")
            }
        }
    }

    private fun showPluginConfig(plugin: InstalledPlugin) {
        val dialogLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(12), dp(20), dp(8))
        }
        val config = EditText(this).apply {
            hint = "Configuração JSON (objeto)"
            setText(plugin.configJson)
            minLines = 5
            gravity = Gravity.TOP
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
        }
        dialogLayout.addView(config, matchWidth())
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Configurar ${plugin.name}")
            .setView(dialogLayout)
            .setNegativeButton("Cancelar", null)
            .setPositiveButton("Salvar") { _, _ ->
                runCatching {
                    val raw = config.text.toString()
                    require(raw.toByteArray(Charsets.UTF_8).size <= 8 * 1024) { "Configuração excede 8 KB" }
                    JSONObject(raw)
                    lifecycleScope.launch {
                        withContext(Dispatchers.IO) { db.installedPluginDao().saveConfig(plugin.pluginId, raw) }
                        toast("Configuração salva")
                        render(Page.PLUGINS)
                    }
                }.onFailure { toast("JSON inválido: ${it.message}") }
            }
            .show()
    }

    private fun openPluginEngine(plugin: InstalledPlugin) {
        if (!plugin.enabled || !pluginEnabled(plugin.engine)) {
            toast("Ative o plugin e seu adaptador na central de Plugins")
            return
        }
        when (plugin.engine) {
            "web_scan" -> { consoleModule = "web"; render(Page.CONSOLE) }
            "api_scan" -> { consoleModule = "api"; render(Page.CONSOLE) }
            "dirb_discovery" -> { consoleModule = "dirb"; render(Page.CONSOLE) }
            "apk_static" -> render(Page.ANDROID)
            "nvd_lookup" -> render(Page.DATABASE)
            "zap_remote", "mobsf_remote", "nmap_agent" -> showConnectorConfig(plugin)
            else -> toast("Adaptador indisponível")
        }
    }

    private fun showConsole() {
        pageBody.addView(label("APOSTULOS Console", 23f, WHITE, true), matchWrap())
        pageBody.addView(label("Console simplificado de módulos. Não executa comandos do sistema nem carrega exploits do Metasploit. Os testes de rede exigem autorização explícita.", 13f, MUTED), matchWrap())
        val target = field("Alvo autorizado (ex.: https://exemplo.com)")
        pageBody.addView(target, matchWidth())
        val authorized = CheckBox(this).apply {
            text = "Tenho autorização para testar este ativo"
            setTextColor(WHITE)
            buttonTintList = ContextCompat.getColorStateList(this@MainActivity, android.R.color.holo_orange_light)
        }
        pageBody.addView(authorized, matchWidth())
        val command = field("Comando: help, modules, use dirb/web/api, run")
        pageBody.addView(command, matchWidth())
        val consoleIntro = if (consoleModule in setOf("dirb", "web", "api")) {
            "Plugin abriu o módulo $consoleModule. Defina o alvo, confirme autorização e use show options/run."
        } else "APOSTULOS Console 3.0\nDigite help para ver os comandos disponíveis."
        val output = label(consoleIntro, 12f, WHITE).apply {
            typeface = Typeface.MONOSPACE
            setPadding(dp(12), dp(12), dp(12), dp(12))
            background = rounded(PANEL, 12)
        }
        pageBody.addView(output, matchWidth())
        pageBody.addView(actionButton("EXECUTAR COMANDO") {
            val line = command.text.toString().trim()
            when {
                line.equals("help", true) -> output.text = "Comandos:\nhelp\nmodules\nuse dirb | web | api\nset target https://host\nshow options\nrun\nsearch cve termo\n\nApenas auditorias autorizadas. Nenhum exploit é executado."
                line.equals("modules", true) -> output.text = "Módulos disponíveis:\n- dirb: descoberta limitada por HEAD (20 caminhos)\n- web: auditoria passiva de cabeçalhos e cookies\n- api: verificações passivas HTTP/CORS\n- nvd: pesquisa e importação CVE (search cve termo)\n- apk: use a tela Android para selecionar um APK"
                line.startsWith("use ", true) -> {
                    consoleModule = line.substringAfter(' ').trim().lowercase(Locale.ROOT)
                    output.text = if (consoleModule in setOf("dirb", "web", "api")) "Módulo selecionado: $consoleModule\nUse show options para ver as opções." else "Módulo não disponível no Console. Digite modules."
                }
                line.startsWith("set target ", true) -> {
                    val value = line.substring(11).trim()
                    target.setText(value)
                    output.text = "Alvo definido: $value"
                }
                line.equals("show options", true) -> output.text = when (consoleModule) {
                    "dirb" -> "Módulo: dirb\nTARGET: ${target.text}\nWORDLIST: lista interna curta (20 caminhos)\nMétodo: HEAD\nRedirecionamentos: não seguidos\nDownload: desativado"
                    "web", "api" -> "Módulo: $consoleModule\nTARGET: ${target.text}\nMétodo: GET\nEscopo: somente URL informada\nVerificações: cabeçalhos, cookies${if (consoleModule == "api") " e CORS" else ""}\nExploração: desativada"
                    else -> "Selecione um módulo: dirb, web ou api"
                }
                line.equals("run", true) -> {
                    val moduleEnabled = when (consoleModule) {
                        "dirb" -> pluginEnabled("dirb_discovery")
                        "web" -> pluginEnabled("web_scan")
                        "api" -> pluginEnabled("api_scan")
                        else -> false
                    }
                    if (consoleModule !in setOf("dirb", "web", "api")) output.text = "Selecione dirb, web ou api com: use <módulo>"
                    else if (!moduleEnabled) output.text = "Módulo desativado. Ative em Plugins."
                    else if (!authorized.isChecked) output.text = "Bloqueado: confirme que tem autorização para testar o alvo."
                    else {
                        val selectedTarget = target.text.toString().trim()
                        if (selectedTarget.isBlank()) output.text = "Defina TARGET antes de executar."
                        else {
                            val selectedModule = consoleModule
                            output.text = "Executando $selectedModule…\nAguarde a conclusão da auditoria."
                            lifecycleScope.launch {
                                runCatching {
                                    if (selectedModule == "dirb") PentestScanner.scanContentDiscovery(selectedTarget)
                                    else PentestScanner.scanWeb(selectedTarget, if (selectedModule == "api") "API" else "Web")
                                }.onSuccess { (items, summary) ->
                                    withContext(Dispatchers.IO) {
                                        if (items.isNotEmpty()) db.findingDao().addAll(items)
                                        db.scanDao().add(ScanRecord(target = selectedTarget, scanType = "Console/${selectedModule.uppercase(Locale.ROOT)}", status = "Concluída", summary = summary))
                                        db.auditLogDao().add(AuditLog(category = "Console", message = summary))
                                    }
                                    output.text = buildString {
                                        appendLine(summary)
                                        appendLine("\nResultados (${items.size}):")
                                        if (items.isEmpty()) appendLine("Nenhuma observação identificada pelos testes executados.")
                                        items.forEach { appendLine("${it.severity} • ${it.title}\n  ${it.evidence}") }
                                        appendLine("\nOs resultados são indicadores; valide manualmente. A auditoria não executa exploits.")
                                    }
                                }.onFailure { output.text = "Falha na execução: ${it.message ?: it.javaClass.simpleName}" }
                            }
                        }
                    }
                }
                line.startsWith("search cve ", true) -> {
                    val query = line.substring(11).trim()
                    if (query.isBlank()) output.text = "Uso: search cve termo"
                    else if (!pluginEnabled("nvd_lookup")) output.text = "Módulo NVD desativado em Plugins."
                    else {
                        output.text = "Consultando NVD…"
                        lifecycleScope.launch {
                            runCatching { NvdRepository.searchAndImport(query) { db.vulnerabilityDao().upsertAll(it) } }
                                .onSuccess { count ->
                                    val now = System.currentTimeMillis()
                                    db.sourceSyncDao().save(SourceSync("NVD", now, now, count, "OK", "Consulta pelo Console: $query"))
                                    output.text = "NVD: $count registro(s) importado(s)/atualizado(s). Abra Banco para ver CVSS e referências."
                                }
                                .onFailure { error ->
                                    val now = System.currentTimeMillis()
                                    val previous = db.sourceSyncDao().get("NVD")?.lastSuccessAt
                                    db.sourceSyncDao().save(SourceSync("NVD", now, previous, 0, "ERRO", error.message ?: "Falha sem detalhes"))
                                    output.text = "Falha na consulta NVD: ${error.message}"
                                }
                        }
                    }
                }
                else -> output.text = "Comando desconhecido. Digite help."
            }
        }, matchWidth())
        pageBody.addView(label("Este console não implementa execução de exploits. O módulo dirb aqui é uma descoberta conservadora de caminhos por HEAD, não o binário original DIRB.", 12f, MUTED), matchWrap())
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
            Triple("DIRB (externo)", "Ferramenta de enumeração de conteúdo web. No APOSTULOS há um módulo próprio e limitado inspirado nesse fluxo.", "https://dirb.sourceforge.net/"),
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
        c.addView(label("APOSTULOS 3.0.0\nPackage: apostulos.securityproxy\nBanco local: apostulos.db\nProxy local: 127.0.0.1:8888", 13f, MUTED), matchWrap())
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
        "MEDIUM", "LOW" -> GOLD
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
