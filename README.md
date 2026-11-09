# APOSTULOS 2.0 — projeto Android

Projeto Android reconstruído a partir do APK debug enviado. O ZIP recebido continha apenas `app-debug.apk`; não havia fontes Kotlin/Gradle. Por isso esta entrega é um novo projeto-fonte compatível com o identificador observado no APK (`apostulos.securityproxy`), e não uma edição binária do APK antigo.

## O que está incluído

- Login local para `seteowl`, `kind` e `the_symon0`.
- Interface escura com detalhes dourados e páginas independentes: Início, Proxy, VPN, Banco, Web, Android, APIs, Ferramentas, Falhas, Relatórios e Ajustes.
- Banco Room local (`apostulos.db`) com `audit_logs`, `vulnerabilities`, `findings` e `scan_history`.
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

## Ambiente de build

- Android Gradle Plugin: 8.7.3
- Kotlin: 2.0.21
- Compile SDK: 35
- Min SDK: 26
- Target SDK: 35
- Room: 2.6.1

## Uso autorizado

Use o APOSTULOS somente em aplicações, dispositivos e redes que você possui ou para os quais tem autorização expressa. Resultados automáticos são indicadores e precisam de validação humana antes de serem classificados como vulnerabilidades confirmadas.
