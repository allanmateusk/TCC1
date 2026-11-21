# Proposta offline de cutoff de lote

Este comando só escreve um JSON de proposta explicitamente **não autorizador**.
O código Cloudflare permanece desarmado (`APPROVED=null`). Não é recibo de
admissão, não confirma fatos do provedor e não publica ou dispara um Workflow.

No diretório `n20-runtime`:

    python -B -m infra.runpod.n20.prepare_batch_cutoff --operator-facts <fatos.json> --out <novo-caminho-absoluto-fora-do-checkout/offline-proposal.json>

O arquivo de entrada tem exatamente duas chaves de nível superior:

- `protection`: todos os campos de `BatchProtection` descritos em
  `INCREMENTAL_BATCH_PROTECTION.md` / `incremental_batch_protection.py`:
  `batch_id`, `resource_id`, `owner_id`, `datacenter_id`, `pod_name`, `git_sha`,
  `profile_sha256`, `opened_at`, `stop_at`, `hard_deadline`, `max_attempt_seconds`,
  `stale_seconds`, `hourly_compute_microusd`, `fixed_and_other_microusd`,
  `approved_cap_microusd`. Use v4 UUID sem hífens, nome
  `tcc-n20-batch-<uuid-sem-hífens>`, instantes Unix UTC em segundos inteiros,
  `4 h <= hard_deadline-opened_at <= 7 h`, e
  `hard_deadline-stop_at = 300 s`. Declare somente preço/cap acordados.
- `operator_observation`: mesmos `batch_id`, `resource_id`, `owner_id`,
  `datacenter_id` e `pod_name`, mais `status: "RUNNING"`, `cloud: "SECURE"`,
  `stop_enabled: true`, e `observed_at` Unix UTC em segundos. Esta informação
  deve ter até 60 s no momento do comando, dentro dos primeiros cinco minutos
  da alocação. Não contém token, URL assinada, segredo ou credencial.

A proposta guarda o hash da proteção, a estimativa nominal e os hashes dos
arquivos desarmados do HEAD. Não pode substituir um arquivo existente. A chave
terminal fica nula. Antes de liberar trabalho real ainda faltam observação
autenticada e independente da conta/Pod, publicação/instância exata do guard
real com autorização separada, Workflow/versão fixados e observação do passo de
sono pendente na UTC aprovada, entrega de admissão assinada ao Linux e fallback
humano. O timer sintético anterior não comprova esses passos e nenhum token é
necessário para montar a proposta.
