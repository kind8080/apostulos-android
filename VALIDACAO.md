# Validação realizada nesta entrega

## Testes executados no ambiente disponível

- **Login local:** compilado e executado isoladamente; as três contas aceitam `admin/apostulos` e uma senha incorreta é rejeitada.
- **Proxy HTTP:** classe Kotlin compilada isoladamente e testada contra um servidor HTTP local; requisição encaminhada com resposta HTTP 200.
- **Proxy HTTPS CONNECT:** classe Kotlin compilada isoladamente e testada contra um servidor HTTPS local com certificado de laboratório; túnel CONNECT retornou HTTP 200.
- **Integridade do pacote recebido:** ZIP aberto; continha somente `app-debug.apk`.

## Testes ainda necessários

- Build Android completo (`gradle assembleDebug`) em runner com Android SDK.
- Instalação em aparelho Android físico e teste de permissões/serviço em primeiro plano.
- Teste de importação e pesquisa na NVD com internet.
- Teste da interface, navegação, persistência Room, exportação e importação de APK no dispositivo.
- Teste de integração da VPN com um provedor/perfil escolhido. A página atual apenas detecta VPN ativa no Android e abre as configurações; não implementa um provedor próprio.

**Não foi possível executar o build Android completo neste ambiente**, pois ele não possui Gradle nem Android SDK instalados. O workflow `.github/workflows/android.yml` foi incluído para fazer essa compilação no GitHub Actions. A execução do workflow será a primeira verificação integrada do projeto Android.
