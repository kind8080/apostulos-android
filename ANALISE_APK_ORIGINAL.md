# Inspeção do APK original enviado

O arquivo `APOSTULOS-debug.zip` contém um único item: `app-debug.apk` (aprox. 3,75 MB). Não contém `app/src`, arquivos Gradle, código-fonte, wrapper ou workflow.

Indícios encontrados no APK:

- Identificador de pacote observado nas classes: `apostulos.securityproxy`.
- Classes de aplicativo: `MainActivity`, `AppDatabase`, `AuditLog`, `AuditLogDao`, `LocalHttpProxyServer`, `LocalProxyService` e `LocalVpnService`.
- Banco Room com tabela `audit_logs`.
- Proxy local indicado em `127.0.0.1:8888`.
- Strings de interface para iniciar/parar o proxy e autorizar VPN Android.
- Texto embutido no APK informa que o motor de encaminhamento/tunelamento da VPN ainda precisava ser integrado.

Conclusão: a versão-fonte original não estava no ZIP. A pasta `APOSTULOS-FINAL` contém uma reconstrução do projeto, preservando o applicationId observado e ampliando os recursos definidos na conversa.
