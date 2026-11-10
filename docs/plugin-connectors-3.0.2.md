# Conectores externos — APOSTULOS 3.0.2

## OWASP ZAP — consulta de alertas passivos
1. Configure a URL base da instância e a API key, se exigida.
2. Use **TESTAR CONEXÃO** para consultar a versão.
3. Use **IMPORTAR ALERTAS PASSIVOS DO ZAP** para consultar `GET /JSON/core/view/alerts/` (até 100 registros) e importar os alertas para Falhas e Histórico.
4. O APOSTULOS não inicia spider nem active scan. A consulta apenas lê alertas que já existem no ZAP. Se o passive scan ainda estiver processando mensagens, a lista pode estar incompleta.

Referência: https://www.zaproxy.org/docs/api/

## MobSF — análise estática de APK
1. Configure a URL base e a API key.
2. Use **ENVIAR APK E ANALISAR NO MOBSF**.
3. Escolha explicitamente um APK no seletor Android. O arquivo será enviado ao servidor configurado via `POST /api/v1/upload`; em seguida o APOSTULOS solicita a análise estática em `POST /api/v1/scan` (incluindo `hash`, `scan_type` e `file_name`) e lê o relatório por `POST /api/v1/report_json`.
4. Os indicadores retornados são importados em Falhas e Histórico, vinculados ao hash retornado pelo MobSF.

**Privacidade:** o APK selecionado sai do aparelho e é enviado ao servidor MobSF. Só envie arquivos próprios ou cujo compartilhamento esteja autorizado. Não há envio automático em segundo plano. Confirme que o servidor MobSF é confiável e protegido por HTTPS.

Referência: https://github.com/MobSF/Mobile-Security-Framework-MobSF

## Nmap Agent
- O Nmap não possui uma API REST oficial padrão.
- O APOSTULOS verifica apenas um agente customizado administrado pelo usuário por `GET /health`, com `X-APOSTULOS-Agent: 1`.
- O teste de saúde não executa Nmap e não representa uma auditoria.

## Transporte e segredos
- HTTPS é obrigatório para hosts externos. HTTP é permitido somente para `localhost`, `127.0.0.1` e `::1`.
- Chaves são guardadas em preferências privadas criptografadas com AES-GCM e uma chave protegida pelo Android Keystore.
- Não inclua API keys em manifestos JSON, URLs ou logs.
- Remover um conector remove também o segredo armazenado.
