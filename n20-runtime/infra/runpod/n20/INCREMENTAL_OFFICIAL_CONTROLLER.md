# Controlador externo do lote oficial (20 casos, um Pod)

Use `Scope.mode="official-full"` **explicitamente** com o plano aprovado
`BatchProtection`, duração total de 4–7 horas e STOP agendado 5 minutos
antes. O digest fixa modo, Pod, owner, data center, lote, Git, perfil,
preço, prazos, chaves e ordem canônica dos 20 cenários. Não reutilize o
diário ou as chaves de uma qualificação. O modo de dois casos, inclusive
a proteção curta de 60 minutos, não consegue validar uma lease para #3.

1. Em controlador privado, configure o mesmo escopo/pins do [handoff
   externo](INCREMENTAL_EXTERNAL_CONTROLLER.md); `Controller.first` obtém
   a observação autêntica e grava a primeira lease no SQLite antes da
   entrega protegida. Nenhuma lease é renovada automaticamente.
2. Para cada lease, construa `FullCaseRelease` com os campos exatos da
   identidade do Pod + guard e, adicionalmente, `scope_sha256`,
   `case_index` (0–19) e `case_deadline`. Seu caso é derivado do índice,
   nunca de input do worker. O controlador recebe pela cópia autenticada
   o ZIP lacrado, valida semântica/perfil/Git/rodadas/ledgers e registra seu
   SHA-256 + tamanho via `seal_full_case` antes do PUT.
3. O assinador de publicação externo fornece envelopes distintos
   `tcc-incremental-full-case-publication/v1`, cada um vinculado ao corpo
   lacrado e à URL SigV4 do seu papel, sem sobreviver ao cutoff do caso.
   O Pod recebe só o PUT condicional, usa
   `publish_full_case_from_pod` e não reenvia automaticamente caso a
   resposta se perca. GET assinado fica apenas fora do Pod, na identidade
   independente de leitura. Nunca entregue tokens duradouros ao Pod.
4. `accept_full_case` lê o objeto independente e só avança se a prova
   combinar com o lacre e o guard tiver observação fresca. Em uma
   transação, registra GET e uma lease para o único cenário seguinte,
   com UUID novo. Só depois assina o relay durável no nome exato
   `warm-transition-02.json` … `warm-transition-20.json` para entrega
   pelo instalador protegido. Não existe STOP entre casos; não existem
   casos em paralelo nem reemissão automática de lease. Falha definitiva
   do conteúdo grava halt irreversível no diário; uma ausência GET
   temporária não avança e pode reconciliar apenas o mesmo objeto.
   Falha do caso e cancelamento podem ser latched via `halt_full_case`.
5. No #20, não forneça `next_run_id`. Só depois do 20º GET e do commit
   final sai `controller-full-final.json` com os 20 recibos em ordem,
   hash canônico do conjunto, papel GET separado e atestação de conclusão.
   O recibo não autoriza #21 nem envia STOP: o guard independente continua
   a única autoridade de parada. Opcionalmente, o observador pode pinçar
   `terminal_pub_key` com 32 bytes Ed25519, Base64URL canônico sem
   padding, de uma quinta autoridade separada, conforme o plano do guard.
   O próximo adaptador deve verificar o conjunto/recibos e só então
   assinar o terminal do guard. Nunca promover a assinatura curta a STOP
   do lote. Sem essa ligação, o cutoff absoluto/manual é o fallback.

A janela de observação mais curta ainda exige renovar o guard após cada
GET, antes dos últimos cinco minutos até o STOP. Se expirar entre commit
e entrega, preserve dados e reconcilie; não reexecute um caso.

**Estado:** integração local, não autorização de lançamento. É necessário
validar R2 real antes de Start; então escolher e validar o hardware ativo,
autorizar e qualificar timer/versões hospedados, fixar chaves/ACLs e
comprovar instalação protegida, cópia de ZIP, transporte/signers de
produção e STOP/EXITED. Fixtures usam HTTP e métricas sintéticas, chaves
efêmeras; 20 recibos de fixture não são 20 experimentos científicos.
