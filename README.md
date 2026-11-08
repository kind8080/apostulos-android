# APOSTULOS Android

Base inicial em Kotlin: login local, painel WebView e registro de eventos com Room.

Contas locais de demonstração:
- `seteowl`
- `kind`
- `the_symon0`

Senha comum: `admin/apostulos`

**Aviso:** credenciais de demonstração estão no código e não devem ser usadas para proteger dados reais nem reutilizadas em outros serviços.

## Compilar pelo GitHub Actions
1. Envie todos os arquivos deste projeto para a raiz do repositório.
2. Abra a aba **Actions** e habilite workflows se solicitado.
3. Execute **Build APOSTULOS APK** em **Run workflow** ou faça um commit.
4. Abra a execução concluída e baixe o artefato `APOSTULOS-debug`.

## Escopo
Esta versão inicial inclui login, painel e gravação de eventos de login no Room. O proxy ainda não foi implementado nem escuta portas. Recursos de inspeção devem ser usados somente em sistemas próprios ou autorizados.
