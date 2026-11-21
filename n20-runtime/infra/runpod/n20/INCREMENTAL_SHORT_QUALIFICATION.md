# Qualificação warm de dois casos em 60 minutos (desarmada)

Este modo não abre o lote de 20. A seleção explícita e assinada
`qualification-60m-two-case` limita a fila e as leases aos dois primeiros
cenários do perfil incremental. O launcher frio recusa o modo curto e
a execução normal continua exigindo **4–7 horas**, sem mudança no
payload padrão. Os dois modos não aceitam provas um do outro.

- O tempo parte do `startedAt` oficial do Pod exato. Tentar STOP em
  **Start +55 min** e confirmar `EXITED` até **Start +60 min**.
  Os 5 minutos finais são reserva, não tempo de trabalho.
- A estimativa nominal para autorização é **1 hora do preço do Pod todo
  + taxas/armazenamento previstos**. Não é um limite de fatura do provedor.
- Use somente a configuração separada
  `cloudflare_batch_cutoff/wrangler.qualification.jsonc`.
  Nomes próprios de Worker/Workflow, sem URL pública, preview, cron ou terminal
  antecipado; a fonte continua `APPROVED=null`. Nunca armar esse Pod também
  no guard legado ou de campanha.
- Para a proposta offline, inclua `qualification_mode` em `protection`,
  `stop_at=opened_at+3300` e `hard_deadline=opened_at+3600`. No documento de
  observação, incluir o mesmo modo no `linux_trust`. O código Cloudflare
  exige o campo correspondente `qualificationMode` sob a versão curta,
  tanto no payload fixado quanto no resultado de bind observado.
- Antes de qualquer partida paga: confirme preço/volume/DC/GPU e ID do
  Pod/autorização exatos; prepare autoridade de STOP, trust/assinador
  independente, instalação protegida, pacote/release, diagnóstico R2 e
  fallback humano. Não toque no piloto anterior nem reaproveite UUID/Pod.
- Após partida autorizada, se não houver bind e sleep autenticados no
  prazo de cinco minutos, não inicie inferência: faça Stop manual, nunca
  Terminate, e confira o estado do Pod exato. Se o cutoff não confirmar
  `EXITED`, use a retaguarda manual dentro da janela. Mesmo parado, o
  armazenamento associado pode continuar sendo cobrado.

Dry-run e fixtures são apenas testes locais. Neste passo não houve deploy,
instalação de trust, prova BF16 warm nem provedor real. O Runtime não recebe
autorização de terceiros casos nem credenciais de STOP.
