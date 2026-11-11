# APOSTULOS — arquitetura híbrida Android + Kali Linux

## Decisão

- **Android local:** UI, login local existente, proxy local, estado VPN Android, Room, verificações passivas Web/API, triagem estática APK, catálogo declarativo e conectores ZAP/MobSF.
- **Kali remoto:** ambiente Linux isolado em servidor/VM controlado pelo proprietário, conectado pelo Kali Linux Bridge.
- **Sincronização:** continua sendo responsabilidade de uma API/backend autenticado; o bridge Kali não é banco de dados nem substitui Room.

## Estado entregue nesta etapa

1. Navegação inferior compacta com cinco grupos, mantendo todos os módulos atuais acessíveis.
2. Conector `nmap_agent` passa a representar o Kali Linux Bridge, autenticar por token e ler `/api/v1/capabilities`.
3. A chave do bridge é armazenada pelo `PluginSecretStore` (Android Keystore), em vez de usar o marcador fixo `1`.
4. Serviço FastAPI em `kali-agent/`, imagem Kali Rolling, inventário de ferramentas e Compose com hardening básico.
5. O endpoint de capacidades declara `execution_enabled=false`. Nenhum comando remoto é aceito nesta fase.

## Próximas fases necessárias

- Fase 2: definir API de jobs tipados (sem shell arbitrário), escopo de alvos aprovado, allowlist de ferramentas/opções, timeout, limites de saída e cancelamento.
- Fase 3: resultados normalizados e importação auditável para Findings/Scan History.
- Fase 4: backend de nuvem para identidade, sincronização Room, catálogo assinado e gestão de instâncias; não armazenar chaves no manifesto JSON.
- Fase 5: testes de integração, testes de autorização/escopo e revisão de segurança antes de habilitar execução remota.

## Limites

- “Ambos” significa Android local + Kali remoto; não significa que Kali seja instalado dentro do APK.
- O bridge atual apenas identifica a instância e lista binários presentes; ainda não inicia Nmap/Nuclei/SQLmap ou outras ferramentas.
- Para conexão fora do servidor, usar HTTPS válido, proxy reverso, firewall e autenticação forte. Não publicar diretamente a porta 8765.
- A execução local Android continua limitada aos adaptadores Kotlin existentes; não executa shell, DEX de terceiros ou binários Linux.
