package apostulos.securityproxy.data

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase

@Entity(tableName = "audit_logs")
data class AuditLog(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val category: String,
    val message: String,
    val createdAt: Long = System.currentTimeMillis()
)

@Entity(tableName = "vulnerabilities", indices = [Index(value = ["cve"], unique = true)])
data class Vulnerability(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val title: String,
    val category: String,
    val cve: String? = null,
    val cwe: String? = null,
    val severity: String,
    val description: String,
    val remediation: String,
    val referenceUrl: String,
    val updatedAt: Long = System.currentTimeMillis()
)

@Entity(tableName = "findings")
data class Finding(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val target: String,
    val title: String,
    val category: String,
    val severity: String,
    val confidence: String,
    val evidence: String,
    val recommendedTool: String,
    val remediation: String,
    val referenceUrl: String = "",
    val status: String = "Aberta",
    val createdAt: Long = System.currentTimeMillis()
)

@Entity(tableName = "scan_history")
data class ScanRecord(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val target: String,
    val scanType: String,
    val status: String,
    val summary: String,
    val createdAt: Long = System.currentTimeMillis()
)

@Dao
interface AuditLogDao {
    @Insert suspend fun add(item: AuditLog)
    @Query("SELECT * FROM audit_logs ORDER BY createdAt DESC LIMIT 100") suspend fun latest(): List<AuditLog>
    @Query("SELECT COUNT(*) FROM audit_logs") suspend fun count(): Int
}

@Dao
interface VulnerabilityDao {
    @Insert(onConflict = OnConflictStrategy.IGNORE) suspend fun insertAll(items: List<Vulnerability>): List<Long>
    @Query("SELECT * FROM vulnerabilities ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END, title LIMIT 250") suspend fun all(): List<Vulnerability>
    @Query("SELECT * FROM vulnerabilities WHERE title LIKE '%' || :q || '%' OR cve LIKE '%' || :q || '%' OR cwe LIKE '%' || :q || '%' OR description LIKE '%' || :q || '%' ORDER BY title LIMIT 100") suspend fun search(q: String): List<Vulnerability>
    @Query("SELECT COUNT(*) FROM vulnerabilities") suspend fun count(): Int
}

@Dao
interface FindingDao {
    @Insert suspend fun add(item: Finding): Long
    @Insert suspend fun addAll(items: List<Finding>)
    @Query("SELECT * FROM findings ORDER BY createdAt DESC LIMIT 300") suspend fun all(): List<Finding>
    @Query("SELECT COUNT(*) FROM findings") suspend fun count(): Int
    @Query("SELECT COUNT(*) FROM findings WHERE severity IN ('HIGH','CRITICAL')") suspend fun highCount(): Int
    @Query("UPDATE findings SET status = :status WHERE id = :id") suspend fun updateStatus(id: Long, status: String)
    @Query("SELECT COUNT(*) FROM findings WHERE title = :title AND target = :target AND createdAt > :since") suspend fun countRecent(title: String, target: String, since: Long): Int
}

@Dao
interface ScanDao {
    @Insert suspend fun add(item: ScanRecord): Long
    @Query("SELECT * FROM scan_history ORDER BY createdAt DESC LIMIT 100") suspend fun all(): List<ScanRecord>
    @Query("SELECT COUNT(*) FROM scan_history") suspend fun count(): Int
}

@Database(
    entities = [AuditLog::class, Vulnerability::class, Finding::class, ScanRecord::class],
    version = 1,
    exportSchema = false
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun auditLogDao(): AuditLogDao
    abstract fun vulnerabilityDao(): VulnerabilityDao
    abstract fun findingDao(): FindingDao
    abstract fun scanDao(): ScanDao

    companion object {
        @Volatile private var INSTANCE: AppDatabase? = null
        fun get(context: Context): AppDatabase = INSTANCE ?: synchronized(this) {
            INSTANCE ?: Room.databaseBuilder(
                context.applicationContext,
                AppDatabase::class.java,
                "apostulos.db"
            ).fallbackToDestructiveMigration().build().also { INSTANCE = it }
        }
    }
}

object VulnerabilitySeed {
    suspend fun install(db: AppDatabase) {
        if (db.vulnerabilityDao().count() > 0) return
        val entries = listOf(
            Vulnerability(title = "SQL Injection", category = "Web/API", cwe = "CWE-89", severity = "CRITICAL", description = "Entrada controlável pelo usuário pode alterar uma consulta SQL quando concatenada sem parametrização. A presença deve ser confirmada em ambiente autorizado.", remediation = "Use consultas parametrizadas, ORM com binding, validação por allowlist e privilégios mínimos no banco.", referenceUrl = "https://owasp.org/www-community/attacks/SQL_Injection"),
            Vulnerability(title = "Cross-Site Scripting (XSS)", category = "Web", cwe = "CWE-79", severity = "HIGH", description = "Dados não confiáveis podem ser interpretados como conteúdo executável pelo navegador.", remediation = "Codifique a saída conforme o contexto, sanitize HTML quando necessário e aplique Content-Security-Policy.", referenceUrl = "https://owasp.org/www-community/attacks/xss/"),
            Vulnerability(title = "Broken Access Control", category = "Web/API", cwe = "CWE-284", severity = "HIGH", description = "Controles de autorização insuficientes podem permitir acesso a recursos de outro usuário ou função.", remediation = "Valide autorização no servidor em cada requisição e teste acesso horizontal e vertical com contas de teste.", referenceUrl = "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
            Vulnerability(title = "Cross-Site Request Forgery (CSRF)", category = "Web", cwe = "CWE-352", severity = "MEDIUM", description = "Uma aplicação pode aceitar ações autenticadas sem comprovar a intenção do usuário.", remediation = "Use tokens CSRF, cookies SameSite, validação de Origin/Referer e reautenticação em ações sensíveis.", referenceUrl = "https://owasp.org/www-community/attacks/csrf"),
            Vulnerability(title = "Security Misconfiguration", category = "Web/API", cwe = "CWE-16", severity = "MEDIUM", description = "Configurações padrão, cabeçalhos ausentes, serviços expostos ou mensagens detalhadas podem ampliar a superfície de ataque.", remediation = "Adote configuração segura, remova serviços desnecessários, atualize componentes e revise cabeçalhos e permissões.", referenceUrl = "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
            Vulnerability(title = "Cryptographic Failures", category = "Web/Android", cwe = "CWE-327", severity = "HIGH", description = "Uso de criptografia fraca, transporte sem proteção ou armazenamento inadequado pode expor dados sensíveis.", remediation = "Use TLS moderno, algoritmos atuais, Android Keystore e evite armazenar segredos em texto puro.", referenceUrl = "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"),
            Vulnerability(title = "Insecure Data Storage", category = "Android", cwe = "CWE-922", severity = "HIGH", description = "Dados sensíveis podem ser armazenados em arquivos, preferências, logs ou bancos sem proteção suficiente.", remediation = "Minimize dados armazenados, use Android Keystore, criptografia apropriada e não grave tokens ou senhas em logs.", referenceUrl = "https://mas.owasp.org/MASTG/"),
            Vulnerability(title = "Insecure Communication", category = "Android/API", cwe = "CWE-319", severity = "HIGH", description = "Comunicação sem criptografia adequada pode expor dados em trânsito.", remediation = "Exija HTTPS, valide certificados normalmente, desative cleartextTraffic e não implemente trust-all.", referenceUrl = "https://mas.owasp.org/MASTG/"),
            Vulnerability(title = "Improper Platform Usage", category = "Android", cwe = "CWE-250", severity = "MEDIUM", description = "Permissões, componentes exportados ou recursos da plataforma podem estar configurados de forma excessiva.", remediation = "Revise permissões, exported, intents, deep links e use o menor privilégio necessário.", referenceUrl = "https://mas.owasp.org/MASTG/"),
            Vulnerability(title = "API Broken Object Level Authorization", category = "API", cwe = "CWE-639", severity = "HIGH", description = "A API pode confiar em identificadores fornecidos pelo cliente sem verificar a autorização do objeto.", remediation = "Faça autorização no servidor para cada objeto e usuário; não confie apenas em IDs imprevisíveis.", referenceUrl = "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"),
            Vulnerability(title = "API Unrestricted Resource Consumption", category = "API", cwe = "CWE-770", severity = "MEDIUM", description = "Ausência de limites pode permitir consumo excessivo de recursos e indisponibilidade.", remediation = "Aplique rate limiting, limites de tamanho, paginação, timeouts e quotas por identidade.", referenceUrl = "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"),
            Vulnerability(title = "Sensitive Data Exposure in Logs", category = "Android/Web/API", cwe = "CWE-532", severity = "MEDIUM", description = "Tokens, credenciais ou dados pessoais em logs podem ser acessados por terceiros ou ferramentas de diagnóstico.", remediation = "Redija dados sensíveis, limite acesso aos logs e evite registrar segredos.", referenceUrl = "https://cwe.mitre.org/data/definitions/532.html")
        )
        db.vulnerabilityDao().insertAll(entries)
    }
}
