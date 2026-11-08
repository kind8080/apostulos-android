# APOSTULOS Android

Projeto Android em Kotlin com login local, painel nativo, banco Room, proxy HTTP local e preparação de autorização VPN.

## Contas locais de demonstração
- `seteowl`
- `kind`
- `the_symon0`

Senha comum: `admin/apostulos`

> Credenciais de demonstração estão no código. Não use esta autenticação para proteger dados reais.

## Recursos desta versão
- Painel nativo com ações para iniciar/parar o proxy.
- Proxy HTTP forward com suporte a `CONNECT` para túneis HTTPS.
- Proxy escuta exclusivamente em `127.0.0.1:8888`, não na rede Wi-Fi/LAN.
- Serviço em primeiro plano com notificação persistente enquanto o proxy HTTP está ativo.
- Registros locais de login e ações no Room.
- Declaração do `VpnService` e fluxo de consentimento do Android.

## Limitação importante da VPN
Esta versão solicita e registra a autorização VPN, mas **não cria uma interface TUN nem encaminha pacotes**. O motor VPN (por exemplo, tun2socks com tratamento de DNS, IPv4/IPv6 e encerramento seguro) precisa ser integrado e testado antes de ativar o roteamento. O aplicativo informa isso claramente e não afirma que o tráfego está protegido ou roteado pela VPN.

## Proxy HTTP
Configure um cliente compatível para usar `127.0.0.1` porta `8888` no próprio dispositivo. O proxy é local ao aparelho; não o exponha à internet. O suporte inicial cobre HTTP sem transferência chunked e túneis CONNECT nas portas 443 e 8443. Requisições HTTP com `Transfer-Encoding` chunked retornam 501 nesta versão.

## Compilar pelo GitHub Actions
1. Envie o conteúdo desta pasta para a raiz do repositório.
2. Abra **Actions** e execute **Build APOSTULOS APK** ou faça um commit na branch `main`.
3. Baixe o artefato `APOSTULOS-debug` quando a execução terminar.

## Segurança e escopo
Use somente em dispositivos, redes e sistemas próprios ou com autorização explícita. O proxy está limitado ao loopback para evitar que outros dispositivos usem o aparelho como proxy aberto.
