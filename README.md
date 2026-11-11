# APOSTULOS 3.0 — projeto Android

Projeto Android reconstruído a partir do APK debug enviado. O ZIP recebido continha apenas `app-debug.apk`; não havia fontes Kotlin/Gradle. Por isso esta entrega é um novo projeto-fonte compatível com o identificador observado no APK (`apostulos.securityproxy`), e não uma edição binária do APK antigo.

## O que está incluído

- Console simplificado com comandos próprios (`help`, `modules`, `use dirb`, `set target`, `show options`, `run` e `search cve`). Não é um shell Android e não executa módulos/exploits do Metasploit.
- Central gráfica de plugins: módulos internos ativáveis/desativáveis, catálogo de conectores OWASP ZAP, MobSF e agente Nmap, importação de pacotes JSON, atualização por versão superior, configuração, ativação, teste de conectividade, logs e remoção.
- Conectores remotos: consulta de alertas existentes do OWASP ZAP (passivo, sem iniciar active scan), upload/análise estática de APK no MobSF após seleção explícita do usuário e health check de agente Nmap customizado. As chaves são protegidas por AES-GCM/Android Keystore; endpoints externos exigem HTTPS.
- Pacotes externos usam manifesto `apostulos-plugin` v1 e só podem selecionar adaptadores Kotlin internos aprovados (`web_scan`, `api_scan`, `apk_static`, `nvd_lookup`, `dirb_discovery`). O pacote não pode fornecer DEX, bibliotecas nativas, shell ou código arbitrário.
- Descoberta conservadora de conteúdo web inspirada no DIRB: lista interna de 20 caminhos, requisições `HEAD`, sem baixar arquivos e sem seguir redirecionamentos. Não é o binário original DIRB.
- Banco Room versão 4 com migrações preservando os dados das versões 1 e 2, CVSS (score/vetor), vetor de ataque, produtos CPE, EPSS, sinalização CISA KEV e datas de publicação/modificação.
- Importação NVD com atualização de registros existentes, suporte a métricas CVSS 4.0, 3.1, 3.0 e 2.0 e cálculo do rótulo de severidade a partir do score quando disponível.
- Atualização sob demanda de EPSS (FIRST) e CISA Known Exploited Vulnerabilities (KEV), com estado da última tentativa e da última sincronização bem-sucedida por fonte.

- Login local para `seteowl`, `kind` e `the_symon0`.
- Interface escura com detalhes dourados e páginas independentes: Início, Proxy, VPN, Banco, Web, Android, APIs, Ferramentas, Falhas, Relatórios e Ajustes.
- Banco Room local (`apostulos.db`) com `audit_logs`, `vulnerabilities`, `findings`, `scan_history`, `source_sync` e `installed_plugins`.
- Base inicial de referências OWASP/CWE para Web, Android e APIs.
- Pesquisa/importação de CVEs pela API pública NVD 2.0 (sob demanda e sujeita a limites de uso da NVD).
- Proxy HTTP local em `127.0.0.1:8888`, com encaminhamento HTTP e túnel TCP `CONNECT` para HTTPS. O conteúdo HTTPS continua criptografado; não há MITM nem instalação de certificado.
- Registro automático de tráfego HTTP sem TLS observado pelo proxy e criação de um achado correlacionado com CWE-319 / comunicação insegura.
- Monitoramento do estado VPN exposto pelo Android e atalho para as configurações do sistema.
- Análise passiva de cabeçalhos HTTP/cookies para Web e APIs.
- Análise estática heurística local de APK (strings DEX, URLs HTTP e padrões de possíveis segredos).
- Recomendações de ferramentas e orientação de correção.
- Exportação de relatório em texto pelo compartilhamento Android.
- GitHub Actions para compilar `assembleDebug` e publicar o APK como artefato.


## Plugins externos declarativos (manifesto JSON)

Na página **Plugins**, use **Importar pacote de plugin (.JSON)**. O arquivo deve conter um manifesto de até 64 KB, com `format`, `manifestVersion`, `id`, `name`, `version`, `description` e `engine`. Exemplo em `docs/plugin-example.json`. O plugin instalado aparece na interface com ativação, configuração JSON, abertura do adaptador e remoção.

**Modelo de segurança:** esta versão importa metadados e configurações, não executáveis. O campo `engine` é validado por allowlist e encaminha para código Kotlin já incluído no aplicativo. Não existe carregamento dinâmico de DEX/JAR/APK, execução de comandos ou instalação de bibliotecas nativas. Assim, plugins externos podem empacotar perfis/atalhos declarativos para os adaptadores disponíveis; plugins de terceiros com lógica própria, assinatura criptográfica, sandbox e atualização remota ainda não estão implementados. Atualizações declarativas são importadas pelo usuário e só aceitam uma versão superior à instalada. O JSON de configuração é armazenado por plugin; opções específicas só terão efeito quando o respectivo adaptador as consumir.

A migração Room 3→4 cria `installed_plugins` sem apagar tabelas anteriores.

## Limites importantes (não são apresentados como funções prontas)

1. **VPN própria:** a página verifica se existe uma VPN ativa no Android e abre as configurações do sistema. Ela não implementa um provedor ou túnel WireGuard/OpenVPN. Para isso é necessário escolher um protocolo/provedor e integrar seu motor oficial, além de uma configuração de servidor válida. O aplicativo não simula uma conexão VPN.
2. **Proxy HTTPS:** `CONNECT` encaminha bytes TLS sem descriptografá-los. O proxy registra host/porta, mas não consegue ver caminhos HTTP ou conteúdo HTTPS sem um mecanismo MITM, certificado instalado e autorização explícita.
3. **Análise Web/API:** verifica a resposta inicial e indicadores de hardening. Não faz exploração, fuzzing, brute force, enumeração agressiva ou confirmação automática de SQLi/XSS/controle de acesso.
4. **Análise Android:** é uma triagem heurística, não substitui MobSF, JADX, testes dinâmicos ou revisão manual. A leitura do manifesto binário é limitada.
5. **Base de vulnerabilidades:** a base inicial é compacta e educativa. CVEs adicionais são importados por pesquisa na NVD; não é um espelho completo e atualizado de todos os CVEs.
6. **Credenciais:** as três contas mantêm a senha inicial comum solicitada (`admin/apostulos`). O código compara o hash SHA-256, mas a senha compartilhada não é adequada para distribuição pública. Troca individual de senha, salt/KDF forte e recuperação de conta devem ser implementados antes de publicar o app.
7. **Capa:** há uma ilustração temporária original de personagem mascarado. A imagem específica de Amigo (20th Century Boys) não foi incluída porque o gerador de imagens estava indisponível durante esta entrega; o recurso `res/drawable/cover_placeholder.xml` é o ponto de substituição.

## Compilar pelo GitHub Actions

1. Faça backup do repositório atual.
2. Substitua os arquivos do repositório pelo conteúdo desta pasta, preservando `.github/workflows/android.yml`.
3. Envie para a branch `main`.
4. Abra **Actions → Build APOSTULOS APK**.
5. Quando a execução terminar com sucesso, baixe o artefato `APOSTULOS-debug`.

O workflow usa Java 17 e Gradle 8.x configurado pela action oficial. O APK será gerado em `app/build/outputs/apk/debug/app-debug.apk`.

## Gravidade e interpretação dos dados

- CVSS: Crítica 9,0–10,0; Alta 7,0–8,9; Média 4,0–6,9; Baixa 0,1–3,9; sem score fica como desconhecida/informativa conforme o achado. A pontuação não é inventada para achados heurísticos.
- EPSS é exibido como probabilidade estimada de exploração, não como severidade.
- CISA KEV sinaliza CVEs presentes no catálogo de vulnerabilidades conhecidamente exploradas.
- Produtos CPE são mostrados quando a resposta NVD fornece dados de configuração/afetação. A interpretação de versões afetadas ainda requer conferência do advisory do fabricante.

## Limites herdados nesta versão 3.0

- O módulo chamado `dirb` no Console é uma implementação Kotlin conservadora de descoberta de caminhos por `HEAD`; não empacota nem executa o programa DIRB original e não baixa conteúdo de endpoints.
- Os conectores ZAP e MobSF agora executam as operações descritas na seção abaixo. O conector Nmap continua limitado ao health check de um agente REST customizado; não instala nem executa Nmap no Android.
- O Console implementa comandos próprios e não é compatível com comandos Metasploit nem executa exploits.
- EPSS e CISA KEV são atualizados sob demanda e dependem de conectividade e disponibilidade das fontes públicas.
- As análises heurísticas continuam sendo triagem. Uma resposta HTTP ou ausência de cabeçalho não confirma, isoladamente, uma vulnerabilidade explorável.

## Conectores externos e limites da integração

- **OWASP ZAP:** além do teste de versão, o botão Importar alertas passivos consulta `GET /JSON/core/view/alerts/` (máximo de 100) e grava indicadores em Falhas/Histórico. Não inicia spider nem active scan; importa somente alertas já presentes na instância.
- **MobSF:** após o usuário selecionar um APK, o app envia o arquivo para `POST /api/v1/upload`, solicita análise estática por `POST /api/v1/scan` e importa os indicadores de `POST /api/v1/report_json`. O arquivo é transmitido ao servidor MobSF; use apenas APKs que você tem autorização para compartilhar.
- **Nmap Agent:** o botão Testar conexão consulta `GET /health` e envia `X-APOSTULOS-Agent: 1`. Esse endpoint é um contrato mínimo customizado para um agente que o administrador hospeda; não é endpoint oficial do Nmap e não executa varreduras nesta versão.
- Chaves API ficam em preferências criptografadas com chave AES-GCM protegida pelo Android Keystore. Não coloque tokens no JSON do manifesto. Remover o plugin também apaga o segredo associado.
- A central registra importação, atualização, remoção e testes de conectividade no histórico de auditoria.

## Ambiente de build

- Versão do app: 3.0.2 (versionCode 6)
- Android Gradle Plugin: 8.7.3
- Kotlin: 2.0.21
- Compile SDK: 35
- Min SDK: 26
- Target SDK: 35
- Room: 2.6.1

## Uso autorizado

Use o APOSTULOS somente em aplicações, dispositivos e redes que você possui ou para os quais tem autorização expressa. Resultados automáticos são indicadores e precisam de validação humana antes de serem classificados como vulnerabilidades confirmadas.


## APOSTULOS 3.0 — atualização desta base

- Identificação Android atualizada nesta revisão para `versionCode 6` e `versionName 3.0.2`.
- O Console executa agora os módulos internos `dirb`, `web` e `api` por `use <módulo>` + `run`, respeitando o estado do módulo e a confirmação de autorização.
- Os resultados dessas execuções são persistidos em `findings`, `scan_history` e `audit_logs`.
- `search cve <termo>` continua usando a integração NVD existente.
- A análise APK continua disponível pela tela Android, não pelo comando `run` do Console.
- A VPN continua sem encaminhamento de pacotes; não deve ser considerada uma VPN funcional nesta versão.
- O módulo `dirb` continua sendo uma descoberta limitada por HEAD com lista interna de 20 caminhos, não o executável DIRB.
- OWASP ZAP importa alertas existentes sem iniciar active scan. MobSF recebe APK selecionado explicitamente e executa análise estática remota. Nmap requer agente REST externo customizado; o APOSTULOS apenas testa `/health`.

O banco Room agora está na versão 3. A migração 2→3 cria `source_sync` sem apagar dados existentes; a migração 1→2 continua registrada para instalações antigas. A tela Banco mostra o estado de sincronização da NVD, FIRST.org EPSS e CISA KEV. Esta atualização de código ainda precisa passar pela compilação Android e por testes em dispositivo antes de ser considerada validada.


## Priorização contextual de vulnerabilidades (3.0)

A tela Banco apresenta uma prioridade de triagem APOSTULOS separada dos valores oficiais CVSS e EPSS. O cálculo local usa CVSS (peso 7), EPSS (peso 20) e um acréscimo de 20 pontos quando a CVE consta na CISA KEV, limitado a 100. A classificação textual destaca KEV como urgente, CVSS alto/crítico e EPSS elevado. Esse índice é heurístico, não é uma métrica padronizada, não substitui CVSS e não comprova que o ativo auditado esteja vulnerável. Antes de priorizar correções, confirme CPE, faixa de versões afetadas, configuração e exposição real.

A sincronização CISA KEV contabiliza agora somente CVEs que efetivamente corresponderam a registros locais; não confunde o total de entradas do catálogo da CISA com correspondências encontradas no banco. Valores EPSS fora do intervalo 0–1 são descartados.


## APOSTULOS 3.0.2 — operações reais dos conectores

- ZAP: consulta até 100 alertas existentes pela API `core/view/alerts` e importa título, risco, evidência, recomendação e URL. Não inicia spider ou active scan.
- MobSF: adiciona seletor de APK, upload multipart, solicitação de análise estática e leitura do relatório JSON; importa até 300 indicadores deduplicados no banco local. O envio exige ação explícita do usuário.
- Ambos registram execução em `scan_history` e `audit_logs`; resultados aparecem em Falhas.
- Nmap permanece como health check de agente customizado, sem execução de comandos.
- Build Android completo e testes contra instâncias reais ainda pendentes.

## Integração Android + Kali Linux (APOSTULOS 3.1 — etapa inicial)

A arquitetura escolhida é híbrida: os adaptadores já embarcados continuam executando localmente no Android; um nó Kali Linux separado fornece o ambiente de ferramentas Linux remoto. O app não tenta executar binários Kali diretamente no Android.

- O antigo conector de health check foi atualizado para **Kali Linux Bridge** e consulta `GET /api/v1/capabilities` com token `X-APOSTULOS-Agent` protegido pelo Android Keystore.
- O diretório `kali-agent/` contém Dockerfile baseado em Kali Rolling, Compose e API FastAPI para inventariar Nmap, Nuclei, Nikto, SQLmap, WhatWeb, Wapiti e TShark.
- A primeira entrega do agente é intencionalmente somente inventário; não executa comandos remotos. A execução de ferramentas será uma etapa separada, com allowlist de tarefas, autorização explícita por alvo, isolamento por job e auditoria.
- O serviço Compose publica a porta apenas em loopback. Para acesso externo, configure HTTPS e controles de acesso em um proxy reverso; nunca exponha a API diretamente à Internet.
- A navegação foi reorganizada em cinco áreas fixas na parte inferior: Início, Análises, Ferramentas, Plugins e Mais. Os módulos de cada área são abertos por um seletor compacto.

Consulte `kali-agent/README.md` para implantação. Não há servidor gratuito provisionado automaticamente: o administrador precisa fornecer a máquina/VM ou hospedagem e o domínio/HTTPS.
