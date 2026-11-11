# APOSTULOS Kali Linux Bridge

Este primeiro componente liga o app Android a um nó Kali remoto e confirma quais ferramentas estão instaladas. Nesta versão o agente é deliberadamente **inventory-only**: não aceita comandos, scripts, argumentos ou alvos enviados pelo telefone. A execução remota de ferramentas exige uma etapa posterior com tarefas allowlist, validação de escopo/autorização, limites de taxa, trilha de auditoria e isolamento por job.

## Implantação

1. Use um servidor Linux que você administra e instale Docker Engine + Compose.
2. Copie esta pasta para o servidor e entre nela.
3. `cp .env.example .env` e substitua o token por um segredo aleatório forte. Não compartilhe o `.env`.
4. `docker compose up -d --build`
5. O serviço fica publicado somente em `127.0.0.1:8765`. Coloque-o atrás de um proxy HTTPS com autenticação/restrição de IP antes de permitir acesso externo. Não exponha a porta diretamente à Internet.
6. No APOSTULOS, abra Plugins → Kali Linux Bridge → Configurar; informe a URL HTTPS pública protegida e o mesmo token. Salve e teste.

## Endpoints

- `GET /health`: estado do processo (sem dados sensíveis).
- `GET /api/v1/capabilities`: exige `X-APOSTULOS-Agent: <token>`; informa a plataforma, versão, inventário e `execution_enabled=false`.

## Android local + Kali remoto

O app mantém seus adaptadores Android locais (análise heurística de APK, verificações passivas Web/API, proxy e banco Room). O nó Kali é um ambiente remoto separado para ferramentas Linux. O Android não executa automaticamente binários Kali; isso evita instalar/executar código arbitrário no telefone e mantém os dois modos independentes.
