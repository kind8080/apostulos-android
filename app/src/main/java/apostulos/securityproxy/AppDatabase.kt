package apostulos.securityproxy

import android.content.Context
import androidx.room.*

@Entity(tableName = "audit_logs")
data class AuditLog(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val createdAt: Long,
    val category: String,
    val message: String
)

@Dao
interface AuditLogDao {
    @Insert suspend fun insert(log: AuditLog)
    @Query("SELECT * FROM audit_logs ORDER BY createdAt DESC LIMIT 200")
    suspend fun latest(): List<AuditLog>
}

@Database(entities = [AuditLog::class], version = 1, exportSchema = false)
abstract class AppDatabase : RoomDatabase() {
    abstract fun auditLogDao(): AuditLogDao
    companion object {
        @Volatile private var INSTANCE: AppDatabase? = null
        fun get(context: Context): AppDatabase =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext, AppDatabase::class.java, "apostulos.db"
                ).build().also { INSTANCE = it }
            }
    }
}
