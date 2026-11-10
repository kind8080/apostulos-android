# Conectores externos — APOSTULOS 3.0.1

## OWASP ZAP
- Configure a URL base da instância ZAP.
- Configure a API key se a instância exigir.
- O teste de conexão consulta `GET /JSON/core/view/version/`.
- Esta versão não inicia spider, active scan ou passive scan.

## MobSF
- Configure a URL base e a API key.
- O teste consulta `GET /api/v1/scans` com `Authorization: <API_KEY>`.
- Esta versão não envia APK nem inicia análise.

## Nmap Agent
- O Nmap não possui uma API REST oficial padrão.
- O APOSTULOS verifica apenas um agente customizado administrado pelo usuário por `GET /health`, com `X-APOSTULOS-Agent: 1`.
- O teste de saúde não executa Nmap e não representa uma auditoria.

## Transporte e segredos
- HTTPS é obrigatório para hosts externos. HTTP é permitido somente para `localhost`, `127.0.0.1` e `::1`.
- Chaves são guardadas em preferências privadas criptografadas com AES-GCM e uma chave protegida pelo Android Keystore.
- Não inclua API keys em manifestos JSON, URLs ou logs.
- Remover um conector remove também o segredo armazenado.
