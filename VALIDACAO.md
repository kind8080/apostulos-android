# Validação da versão 2.1.0

## Alterações incluídas nesta revisão

- Console simplificado com interpretador de comandos próprios e confirmação de autorização para executar a descoberta web.
- Módulo de descoberta de conteúdo limitado a 20 caminhos fixos, requisições HEAD, sem download de conteúdo e sem seguir redirecionamentos.
- Gerenciador de módulos internos com preferências persistentes para habilitar/desabilitar os módulos.
- Banco Room migrado da versão 1 para a versão 2 sem migração destrutiva, com campos CVSS, vetor, CPE, EPSS, CISA KEV e datas NVD.
- Importação NVD atualizada para CVSS 4.0/3.1/3.0/2.0 e substituição de registros existentes pelo CVE.
- Atualização sob demanda de EPSS (FIRST) e CISA KEV.

## Verificações realizadas nesta preparação

- ZIP de origem aberto e estrutura inspecionada.
- Verificada a existência dos módulos `MainActivity`, `PentestScanner`, `AppDatabase`, proxy e autenticação.
- Revisão estática dos arquivos Kotlin alterados; o compilador Kotlin foi invocado, mas sem Android SDK e dependências AndroidX/Room/coroutines no classpath, portanto não foi possível validar o build Android completo.
- A migração Room 1→2 foi escrita com ALTER TABLE para preservar os registros existentes; precisa ser validada em execução no aparelho/emulador.

## Testes obrigatórios antes de instalar

1. Executar `gradle assembleDebug` pelo GitHub Actions.
2. Instalar o APK em aparelho de teste e confirmar que os dados existentes em `apostulos.db` permanecem após a atualização.
3. Testar consulta NVD e conferir CVSS/vetor/CPE para CVEs com métricas publicadas.
4. Testar atualização EPSS e CISA KEV com internet.
5. Testar o Console somente contra um domínio próprio/laboratório e confirmar que o módulo faz apenas HEAD.
6. Testar ativação/desativação dos módulos e navegação entre páginas.

**Esta revisão ainda não deve ser considerada compilada ou testada em dispositivo.** O resultado final de compilação deve ser confirmado no GitHub Actions antes de substituir o APK instalado.

## Atualização de triagem 3.0 (10/11/2026)
- Compilação isolada do novo `RiskAssessment.kt` com `kotlinc`: aprovada.
- Verificações estáticas de integração entre `MainActivity`, `AppDatabase` e `NvdRepository`: aprovadas.
- Consulta Room passou a ordenar por KEV e índice heurístico combinado CVSS/EPSS.
- Contagem CISA KEV corrigida para contar apenas CVEs correspondentes ao banco local.
- EPSS fora do intervalo 0–1 é descartado.
- Build Android completo: não executado neste ambiente (Android SDK/Gradle indisponíveis). Deve ser validado pelo GitHub Actions antes de distribuir APK.
- Casos de teste executados para prioridade `URGENTE`, `CRÍTICO`, `ALTO` e `INDETERMINADO`: aprovados.


## Atualização da central de plugins

- [x] Criada tabela Room `installed_plugins` e migração 3→4.
- [x] Importação de manifesto JSON via seletor de documentos Android.
- [x] Validação de tamanho, formato, versão do manifesto, ID, SemVer, descrição e adaptador permitido.
- [x] Interface para ativar/desativar, editar configuração JSON, abrir o adaptador e remover plugin.
- [x] Pacotes externos não carregam código executável; somente metadados/configuração e adaptadores internos allowlisted.
- [ ] Compilação Android completa e teste de migração em dispositivo/emulador: pendentes neste ambiente sem Gradle/Android SDK.
- [ ] Assinatura criptográfica de pacotes, sandbox para código de terceiros e atualização remota: não implementadas.


## Atualização 3.0.1 — catálogo e conectores de plugins

- Adicionado catálogo gráfico de conectores OWASP ZAP, MobSF e agente Nmap customizado.
- Instalação/atualização declarativa por versão SemVer superior, preservando configuração e estado instalado.
- Testes de conectividade: ZAP `GET /JSON/core/view/version/`, MobSF `GET /api/v1/scans`, agente `GET /health`.
- API keys protegidas por AES-GCM com chave Android Keystore; removidas ao desinstalar o plugin.
- HTTP bloqueado para hosts externos; HTTPS obrigatório, com exceção de localhost.
- Histórico de eventos de plugins apresentado na interface.
- Limite explícito: ainda não há disparo de scans ZAP, upload/scan MobSF ou execução Nmap.
- Build Android completo não executado neste ambiente (Gradle/Android SDK ausentes).

## Atualização 3.0.2 — operações ZAP/MobSF

- [x] ZAP: consulta somente alertas existentes por `GET /JSON/core/view/alerts/`, com limite de 100, sem iniciar active scan.
- [x] MobSF: seletor explícito de APK, upload multipart, solicitação de análise estática e leitura do relatório JSON.
- [x] Resultados importados para `findings`, `scan_history` e `audit_logs`.
- [x] Documentada a transferência do APK para o servidor MobSF e a exigência de autorização para compartilhar o arquivo.
- [ ] Testes de integração contra instâncias reais ZAP/MobSF e build Android completo: pendentes.
- Nmap continua limitado ao health check de agente REST customizado; não há execução de Nmap pelo app.
