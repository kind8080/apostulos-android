package apostulos.securityproxy

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

private val CatalogPanel = Color(0xFF151D2D)
private val CatalogAccent = Color(0xFF35D0B0)
private val CatalogMuted = Color(0xFF9AA8BD)

@Composable
fun PluginCatalogScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var plugins by remember { mutableStateOf<List<CatalogPlugin>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }

    suspend fun loadCatalog() {
        loading = true
        error = null
        try {
            plugins = PluginCatalogRepository.fetchPlugins()
        } catch (e: Exception) {
            error = e.message ?: "Não foi possível carregar o catálogo."
        } finally {
            loading = false
        }
    }

    LaunchedEffect(Unit) {
        loadCatalog()
    }

    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            "CENTRAL DE FERRAMENTAS",
            color = CatalogAccent,
            fontSize = 13.sp,
            fontWeight = FontWeight.Bold
        )

        Spacer(Modifier.height(8.dp))

        Text(
            "Catálogo de ferramentas publicadas no APOSTULOS.",
            color = CatalogMuted,
            fontSize = 14.sp
        )

        Spacer(Modifier.height(16.dp))

        Button(
            onClick = { scope.launch { loadCatalog() } },
            enabled = !loading,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Atualizar catálogo")
        }

        Spacer(Modifier.height(16.dp))

        if (loading) {
            CircularProgressIndicator(color = CatalogAccent)
            Spacer(Modifier.height(8.dp))
            Text("Carregando ferramentas...", color = CatalogMuted)
        } else if (error != null) {
            Card(
                colors = CardDefaults.cardColors(containerColor = CatalogPanel),
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp)
            ) {
                Column(Modifier.padding(16.dp)) {
                    Text("Falha na conexão", color = Color.White, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(8.dp))
                    Text(error ?: "", color = CatalogMuted, fontSize = 13.sp)
                    Spacer(Modifier.height(12.dp))
                    Button(onClick = { scope.launch { loadCatalog() } }) {
                        Text("Tentar novamente")
                    }
                }
            }
        } else if (plugins.isEmpty()) {
            Card(
                colors = CardDefaults.cardColors(containerColor = CatalogPanel),
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp)
            ) {
                Text(
                    "Nenhuma ferramenta publicada no catálogo ainda.",
                    color = CatalogMuted,
                    modifier = Modifier.padding(16.dp)
                )
            }
        } else {
            Text(
                "${plugins.size} ferramenta(s) encontrada(s)",
                color = CatalogAccent,
                fontSize = 13.sp
            )
            Spacer(Modifier.height(12.dp))

            plugins.forEach { plugin ->
                Card(
                    colors = CardDefaults.cardColors(containerColor = CatalogPanel),
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 12.dp)
                ) {
                    Column(Modifier.padding(16.dp)) {
                        Text(
                            plugin.name,
                            color = Color.White,
                            fontSize = 17.sp,
                            fontWeight = FontWeight.Bold
                        )

                        if (plugin.description.isNotBlank()) {
                            Spacer(Modifier.height(6.dp))
                            Text(plugin.description, color = CatalogMuted, fontSize = 13.sp)
                        }

                        Spacer(Modifier.height(8.dp))

                        val details = listOfNotNull(
                            plugin.engine.takeIf { it.isNotBlank() }?.let { "Motor: $it" },
                            plugin.version.takeIf { it.isNotBlank() }?.let { "Versão: $it" }
                        ).joinToString("  •  ")

                        if (details.isNotBlank()) {
                            Text(details, color = CatalogAccent, fontSize = 12.sp)
                        }

                        if (plugin.officialUrl.startsWith("https://")) {
                            Spacer(Modifier.height(8.dp))
                            TextButton(
                                onClick = {
                                    val intent = Intent(
                                        Intent.ACTION_VIEW,
                                        Uri.parse(plugin.officialUrl)
                                    )
                                    context.startActivity(intent)
                                }
                            ) {
                                Text("Site oficial")
                            }
                        }
                    }
                }
            }
        }
    }
}
