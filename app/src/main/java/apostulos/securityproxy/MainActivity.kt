package apostulos.securityproxy

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private val Background = Color(0xFF090D18)
private val Panel = Color(0xFF151D2D)
private val Accent = Color(0xFF35D0B0)
private val Muted = Color(0xFF9AA8BD)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            ApostulosApp()
        }
    }
}

@Composable
fun ApostulosApp() {
    var selectedTab by remember { mutableIntStateOf(0) }

    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Accent,
            background = Background,
            surface = Panel,
            onBackground = Color.White,
            onSurface = Color.White
        )
    ) {
        Scaffold(
            containerColor = Background,
            bottomBar = {
                NavigationBar(containerColor = Panel) {
                    val tabs = listOf("Início", "Ferramentas", "Sistema")

                    tabs.forEachIndexed { index, label ->
                        NavigationBarItem(
                            selected = selectedTab == index,
                            onClick = { selectedTab = index },
                            icon = {
                                Text(
                                    listOf("⌂", "⚙", "▣")[index],
                                    fontSize = 20.sp
                                )
                            },
                            label = { Text(label) },
                            colors = NavigationBarItemDefaults.colors(
                                selectedIconColor = Accent,
                                selectedTextColor = Accent,
                                indicatorColor = Color(0xFF26394A)
                            )
                        )
                    }
                }
            }
        ) { padding ->
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .verticalScroll(rememberScrollState())
                    .padding(20.dp)
            ) {
                Text(
                    "APOSTULOS",
                    color = Accent,
                    fontSize = 25.sp,
                    fontWeight = FontWeight.Bold
                )

                Text(
                    "Seu ambiente de segurança digital",
                    color = Muted,
                    fontSize = 13.sp
                )

                Spacer(Modifier.height(28.dp))

                when (selectedTab) {
                    0 -> HomeScreen(
                        onToolsClick = { selectedTab = 1 }
                    )
                    1 -> ToolsScreen()
                    2 -> SystemScreen()
                }
            }
        }
    }
}

@Composable
fun HomeScreen(onToolsClick: () -> Unit) {
    Text(
        "Painel principal",
        color = Color.White,
        fontSize = 22.sp,
        fontWeight = FontWeight.Bold
    )

    Spacer(Modifier.height(16.dp))

    Card(
        colors = CardDefaults.cardColors(containerColor = Panel),
        shape = RoundedCornerShape(18.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(20.dp)) {
            Text("AMBIENTE APOSTULOS", color = Accent, fontSize = 12.sp)
            Spacer(Modifier.height(10.dp))
            Text(
                "Seu laboratório Linux na nuvem.",
                color = Color.White,
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold
            )
            Spacer(Modifier.height(8.dp))
            Text(
                "A plataforma está sendo preparada. " +
                    "A conexão com o servidor será adicionada nas próximas etapas.",
                color = Muted,
                fontSize = 14.sp
            )
            Spacer(Modifier.height(18.dp))
            Button(
                onClick = onToolsClick,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Explorar ferramentas")
            }
        }
    }

    Spacer(Modifier.height(22.dp))
    SectionTitle("ESTADO DO SISTEMA")

    InfoCard("Aplicativo", "Nova base mobile", "Em desenvolvimento")
    InfoCard("Servidor Kali", "Infraestrutura em nuvem", "A configurar")
    InfoCard("Supabase", "Serviços de dados", "Integração pendente")
}

@Composable
fun ToolsScreen() {
    PluginCatalogScreen()
}

@Composable
fun SystemScreen() {
    SectionTitle("CONFIGURAÇÕES DO SISTEMA")
    InfoCard("Conta", "Autenticação e perfil", "Supabase")
    InfoCard("Conexão", "Servidor remoto APOSTULOS", "Não configurado")
    InfoCard("Desktop Linux", "Ambiente XFCE remoto", "Opcional — futuro")
    InfoCard("Interface", "Experiência otimizada para toque", "Modo mobile")
}

@Composable
fun SectionTitle(title: String) {
    Text(
        title,
        color = Accent,
        fontSize = 13.sp,
        fontWeight = FontWeight.Bold
    )
    Spacer(Modifier.height(12.dp))
}

@Composable
fun InfoCard(title: String, description: String, status: String) {
    Card(
        colors = CardDefaults.cardColors(containerColor = Panel),
        shape = RoundedCornerShape(14.dp),
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 12.dp)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(title, color = Color.White, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(4.dp))
                Text(description, color = Muted, fontSize = 12.sp)
            }
            Text(status, color = Accent, fontSize = 11.sp)
        }
    }
}
