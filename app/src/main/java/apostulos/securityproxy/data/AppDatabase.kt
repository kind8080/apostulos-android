
package apostulos.securityproxy.data

import android.content.Context
import androidx.room.*
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

@Entity(tableName = "audit_logs")
data class AuditLog(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val category: String,
    val message: String,
    val createdAt: Long = System.currentTimeMillis()
)

@Entity(
    tableName = "vulnerabilities",
    indices = [Index(value = ["cve"], unique = true)]
)
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
    val updatedAt: Long = System.currentTimeMillis(),
    val cvssScore: Double? = null,
    val cvssVersion: String? = null,
    val cvssVector: String? = null,
    val attackVector: String? = null,
    val epssScore: Double? = null,
    @ColumnInfo(defaultValue = "0") val knownExploited: Boolean = false,
    val publishedAt: Long? = null,
    val modifiedAt: Long? = null,
    @ColumnInfo(defaultValue = "''") val affectedProducts: String = "",
    @ColumnInfo(defaultValue = "'OWASP/CWE'") val source: String = "OWASP/CWE"
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

@Entity(tableName = "installed_plugins")
data class InstalledPlugin(
    @PrimaryKey val pluginId: String,
    val name: String,
    val version: String,
    val description: String,
    val engine: String,
    @ColumnInfo(defaultValue = "'{}'") val configJson: String = "{}",
    @ColumnInfo(defaultValue = "1") val enabled: Boolean = true,
    val installedAt: Long = System.currentTimeMillis()
)

@Entity(tableName = "source_sync")
data class SourceSync(
    @PrimaryKey val source: String,
    val lastAttemptAt: Long,
    val lastSuccessAt: Long? = null,
    @ColumnInfo(defaultValue = "0") val recordsProcessed: Int = 0,
    val status: String,
    @ColumnInfo(defaultValue = "''") val details: String = ""
)

@Dao
interface AuditLogDao {
    @Insert
    suspend fun add(item: AuditLog)

    @Query("SELECT * FROM audit_logs ORDER BY createdAt DESC LIMIT 100")
    suspend fun latest(): List<AuditLog>

    @Query("SELECT COUNT(*) FROM audit_logs")
    suspend fun count(): Int
}

@Dao
interface VulnerabilityDao {
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertAll(items: List<Vulnerability>): List<Long>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(items: List<Vulnerability>)

    @Query("SELECT * FROM vulnerabilities ORDER BY knownExploited DESC, title LIMIT 250")
    suspend fun all(): List<Vulnerability>

    @Query("""
        SELECT * FROM vulnerabilities
        WHERE title LIKE '%' || :q || '%'
        OR cve LIKE '%' || :q || '%'
        OR cwe LIKE '%' || :q || '%'
        OR description LIKE '%' || :q || '%'
        ORDER BY knownExploited DESC, title
        LIMIT 100
    """)
    suspend fun search(q: String): List<Vulnerability>

    @Query("SELECT COUNT(*) FROM vulnerabilities")
    suspend fun count(): Int

    @Query("SELECT cve FROM vulnerabilities WHERE cve IS NOT NULL")
    suspend fun cveIds(): List<String?>

    @Query("UPDATE vulnerabilities SET epssScore = :score, updatedAt = :updatedAt WHERE cve = :cve")
    suspend fun updateEpss(cve: String, score: Double, updatedAt: Long)

    @Query("UPDATE vulnerabilities SET knownExploited = 0")
    suspend fun clearKnownExploited()

    @Query("UPDATE vulnerabilities SET knownExploited = 1 WHERE cve = :cve")
    suspend fun markKnownExploited(cve: String): Int
}

@Dao
interface FindingDao {
    @Insert
    suspend fun add(item: Finding): Long

    @Insert
    suspend fun addAll(items: List<Finding>)

    @Query("SELECT * FROM findings ORDER BY createdAt DESC LIMIT 300")
    suspend fun all(): List<Finding>

    @Query("SELECT COUNT(*) FROM findings")
    suspend fun count(): Int

    @Query("SELECT COUNT(*) FROM findings WHERE severity IN ('HIGH','CRITICAL')")
    suspend fun highCount(): Int

    @Query("UPDATE findings SET status = :status WHERE id = :id")
    suspend fun updateStatus(id: Long, status: String)

    @Query("SELECT COUNT(*) FROM findings WHERE title = :title AND target = :target AND createdAt > :since")
    suspend fun countRecent(title: String, target: String, since: Long): Int
}

@Dao
interface ScanDao {
    @Insert
    suspend fun add(item: ScanRecord): Long

    @Query("SELECT * FROM scan_history ORDER BY createdAt DESC LIMIT 100")
    suspend fun all(): List<ScanRecord>

    @Query("SELECT COUNT(*) FROM scan_history")
    suspend fun count(): Int
}

@Dao
interface InstalledPluginDao {
    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun install(plugin: InstalledPlugin)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(plugin: InstalledPlugin)

    @Query("SELECT * FROM installed_plugins ORDER BY name COLLATE NOCASE")
    suspend fun all(): List<InstalledPlugin>

    @Query("SELECT * FROM installed_plugins WHERE pluginId = :id LIMIT 1")
    suspend fun get(id: String): InstalledPlugin?

    @Query("UPDATE installed_plugins SET enabled = :enabled WHERE pluginId = :id")
    suspend fun setEnabled(id: String, enabled: Boolean)

    @Query("UPDATE installed_plugins SET configJson = :config WHERE pluginId = :id")
    suspend fun saveConfig(id: String, config: String)

    @Query("DELETE FROM installed_plugins WHERE pluginId = :id")
    suspend fun remove(id: String)
}

@Dao
interface SourceSyncDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun save(item: SourceSync)

    @Query("SELECT * FROM source_sync ORDER BY source")
    suspend fun all(): List<SourceSync>

    @Query("SELECT * FROM source_sync WHERE source = :source LIMIT 1")
    suspend fun get(source: String): SourceSync?
}

private val MIGRATION_1_2 = object : Migration(1, 2) {
    override fun migrate(db: SupportSQLiteDatabase) {

        db.execSQL("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                cve TEXT,
                cwe TEXT,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                remediation TEXT NOT NULL,
                referenceUrl TEXT NOT NULL,
                updatedAt INTEGER NOT NULL,
                cvssScore REAL,
                cvssVersion TEXT,
                cvssVector TEXT,
                attackVector TEXT,
                epssScore REAL,
                knownExploited INTEGER NOT NULL DEFAULT 0,
                publishedAt INTEGER,
                modifiedAt INTEGER,
                affectedProducts TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT 'OWASP/CWE'
            )
        """.trimIndent())

        db.execSQL("""
            CREATE UNIQUE INDEX IF NOT EXISTS
            index_vulnerabilities_cve
            ON vulnerabilities(cve)
        """.trimIndent())

        db.execSQL("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                target TEXT NOT NULL,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                evidence TEXT NOT NULL,
                recommendedTool TEXT NOT NULL,
                remediation TEXT NOT NULL,
                referenceUrl TEXT NOT NULL,
                status TEXT NOT NULL,
                createdAt INTEGER NOT NULL
            )
        """.trimIndent())

        db.execSQL("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                target TEXT NOT NULL,
                scanType TEXT NOT NULL,
                status TEXT NOT NULL,
                summary TEXT NOT NULL,
                createdAt INTEGER NOT NULL
            )
        """.trimIndent())
    }
}

private val MIGRATION_2_3 = object : Migration(2, 3) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE IF NOT EXISTS source_sync (
                source TEXT NOT NULL PRIMARY KEY,
                lastAttemptAt INTEGER NOT NULL,
                lastSuccessAt INTEGER,
                recordsProcessed INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT ''
            )
        """.trimIndent())
    }
}

private val MIGRATION_3_4 = object : Migration(3, 4) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE IF NOT EXISTS installed_plugins (
                pluginId TEXT NOT NULL PRIMARY KEY,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                description TEXT NOT NULL,
                engine TEXT NOT NULL,
                configJson TEXT NOT NULL DEFAULT '{}',
                enabled INTEGER NOT NULL DEFAULT 1,
                installedAt INTEGER NOT NULL
            )
        """.trimIndent())
    }
}

@Database(
    entities = [
        AuditLog::class,
        Vulnerability::class,
        Finding::class,
        ScanRecord::class,
        SourceSync::class,
        InstalledPlugin::class
    ],
    version = 4,
    exportSchema = false
)
abstract class AppDatabase : RoomDatabase() {

    abstract fun auditLogDao(): AuditLogDao
    abstract fun vulnerabilityDao(): VulnerabilityDao
    abstract fun findingDao(): FindingDao
    abstract fun scanDao(): ScanDao
    abstract fun sourceSyncDao(): SourceSyncDao
    abstract fun installedPluginDao(): InstalledPluginDao

    companion object {
        @Volatile
        private var INSTANCE: AppDatabase? = null

        fun get(context: Context): AppDatabase =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "apostulos.db"
                )
                    .addMigrations(
                        MIGRATION_1_2,
                        MIGRATION_2_3,
                        MIGRATION_3_4
                    )
                    .build()
                    .also { INSTANCE = it }
            }
    }
}

object VulnerabilitySeed {
    suspend fun install(db: AppDatabase) {
        if (db.vulnerabilityDao().count() > 0) return

        val entries = listOf(
            Vulnerability(
                title = "SQL Injection",
                category = "Web/API",
                cwe = "CWE-89",
                severity = "CRITICAL",
                description = "Entrada controlável pode alterar consultas SQL sem parametrização.",
                remediation = "Use consultas parametrizadas, validação e privilégios mínimos.",
                referenceUrl = "https://owasp.org/www-community/attacks/SQL_Injection"
            ),
            Vulnerability(
                title = "Cross-Site Scripting (XSS)",
                category = "Web",
                cwe = "CWE-79",
                severity = "HIGH",
                description = "Dados não confiáveis podem ser interpretados como conteúdo executável.",
                remediation = "Codifique a saída e aplique Content-Security-Policy.",
                referenceUrl = "https://owasp.org/www-community/attacks/xss/"
            ),
            Vulnerability(
                title = "Broken Access Control",
                category = "Web/API",
                cwe = "CWE-284",
                severity = "HIGH",
                description = "Controles insuficientes podem permitir acesso não autorizado.",
                remediation = "Valide autorização no servidor em cada requisição.",
                referenceUrl = "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
            ),
            Vulnerability(
                title = "Cross-Site Request Forgery (CSRF)",
                category = "Web",
                cwe = "CWE-352",
                severity = "MEDIUM",
                description = "Ações autenticadas podem ser executadas sem intenção do usuário.",
                remediation = "Use tokens CSRF e cookies SameSite.",
                referenceUrl = "https://owasp.org/www-community/attacks/csrf"
            ),
            Vulnerability(
                title = "Security Misconfiguration",
                category = "Web/API",
                cwe = "CWE-16",
                severity = "MEDIUM",
                description = "Configurações inseguras podem ampliar a superfície de ataque.",
                remediation = "Adote configuração segura e remova serviços desnecessários.",
                referenceUrl = "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
            ),
            Vulnerability(
                title = "Cryptographic Failures",
                category = "Web/Android",
                cwe = "CWE-327",
                severity = "HIGH",
                description = "Criptografia fraca pode expor dados sensíveis.",
                remediation = "Use TLS moderno e Android Keystore.",
                referenceUrl = "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
            ),
            Vulnerability(
                title = "Insecure Data Storage",
                category = "Android",
                cwe = "CWE-922",
                severity = "HIGH",
                description = "Dados sensíveis podem ser armazenados sem proteção suficiente.",
                remediation = "Minimize dados armazenados e proteja segredos.",
                referenceUrl = "https://mas.owasp.org/MASTG/"
            ),
            Vulnerability(
                title = "Insecure Communication",
                category = "Android/API",
                cwe = "CWE-319",
                severity = "HIGH",
                description = "Comunicação sem criptografia pode expor dados.",
                remediation = "Exija HTTPS e valide certificados.",
                referenceUrl = "https://mas.owasp.org/MASTG/"
            ),
            Vulnerability(
                title = "Improper Platform Usage",
                category = "Android",
                cwe = "CWE-250",
                severity = "MEDIUM",
                description = "Permissões e componentes podem estar configurados em excesso.",
                remediation = "Revise permissões e use o menor privilégio necessário.",
                referenceUrl = "https://mas.owasp.org/MASTG/"
            ),
            Vulnerability(
                title = "API Broken Object Level Authorization",
                category = "API",
                cwe = "CWE-639",
                severity = "HIGH",
                description = "A API pode não validar autorização sobre cada objeto.",
                remediation = "Faça autorização no servidor para cada objeto e usuário.",
                referenceUrl = "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
            ),
            Vulnerability(
                title = "API Unrestricted Resource Consumption",
                category = "API",
                cwe = "CWE-770",
                severity = "MEDIUM",
                description = "Ausência de limites pode causar consumo excessivo de recursos.",
                remediation = "Aplique limites, paginação, timeouts e quotas.",
                referenceUrl = "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"
            ),
            Vulnerability(
                title = "Sensitive Data Exposure in Logs",
                category = "Android/Web/API",
                cwe = "CWE-532",
                severity = "MEDIUM",
                description = "Tokens e dados pessoais em logs podem ser expostos.",
                remediation = "Redija dados sensíveis e evite registrar segredos.",
                referenceUrl = "https://cwe.mitre.org/data/definitions/532.html"
            )
        )

        db.vulnerabilityDao().upsertAll(entries)
    }
}
