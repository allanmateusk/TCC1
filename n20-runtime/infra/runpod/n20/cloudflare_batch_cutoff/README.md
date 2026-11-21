# Cloudflare batch cutoff candidate (disarmed)

Separate offline candidate for the 20-case campaign, not the pilot. No
deployment, credentials, public route, workers.dev, preview, cron or generic
HTTP relay. The hard UTC deadline is 4–7 hours after independently verified
start. STOP is scheduled 2–10 minutes earlier; use **5 minutes** as the shared
operational reserve, rather than the smaller local-authorizer minimum.

Run `node --test batch-guard.test.mjs` in this directory. An already installed
Wrangler can compile with `deploy --dry-run --config wrangler.jsonc --outdir <scratch>`
and telemetry disabled. This is **not** a hosted Cloudflare timer, deployment,
secret or provider test.

- A separately authorized live plan must pin `batch`, `pod`, `owner`,
  `datacenter`, `name`, `startedAt`, `stopAt`, `deadline`, `gitSha`,
  `profileSha256`, and optional `terminalPubKey` in source. The trigger
  cannot arm by itself. The Workflow instance ID is the exact hyphenated v4
  batch UUID; the controller ID is the same hex without separators. Timestamps
  are canonical UTC with millisecond precision.
- The cutoff persists its plan within five minutes of start, then sleeps in
  `absolute-batch-cutoff`. The dedicated SQLite Durable Object is keyed by
  exact owner plus Pod. It refuses rebinding to another batch/plan; no reset
  or rearm path is provided.
- Optional early completion requires independently verified receipts for all
  20 scenarios and a signed, fresh Ed25519 claim. Leave `terminalPubKey: null`
  until a separate trusted receipt collector, signer and private trigger path
  are qualified. The public key is 32 raw bytes, unpadded Base64URL.
  The signed `proof` is precisely schema `tcc-batch-early-stop/v1`, batch, pod,
  owner, gitSha, profileSha256, verifiedCases=20, receiptSetSha256 (64 hex),
  observedAt (UTC, within 60 seconds); `terminalBytes()` defines the exact byte
  serialization. The 64-byte signature is unpadded Base64URL. A Pod-asserted
  count and local/mock receipts must never be signed as completion proof.
- Cutoff and early completion share one atomic STOP permit (claim before
  POST). A timeout/ambiguous claim leads to GET only, never a second POST.
  The target must exactly match the pinned account, Pod, name, data center,
  Secure Cloud and provider STOP ability. A POST ACK/202 is not evidence of
  stopping; only the exact Pod confirmed EXITED by GET counts. No DELETE.
  Do not enable a competing automated STOP writer (Windows or pilot) for
  the same allocation.
- No credential is provided. A future separately authorized setup keeps the
  key only in Cloudflare as `RUNPOD_BATCH_STOP_TOKEN`, with necessary account
  read and Pods read/write only where supported; that does not imply a
  provider-enforced per-Pod key scope. Do not put private keys or tokens in
  source, payload, Git, logs, Terraform state or on the GPU machine.

Before allocating a GPU, separately qualify the hosted Workflow with no
provider key and no GPU, check the actual deployed Workflow/Worker version
and unfinished absolute timer at the exact UTC, and wire protected Linux
admission to that authenticated observation. The old pilot admission file
does not apply. If no matching timer is confirmed five minutes after start,
or STOP is not verified in its window, use the prearranged manual STOP (not
Terminate) and confirm EXITED. No late automatic POST is sent after the hard
deadline; late verification is read-only. This is at most one automated POST,
not a guarantee of delivery or exact-time Cloudflare resumption. Confirm GPU
charges separately from retained storage. Actual cloud timer, trusted signer
and provider shutdown were not exercised.

References: [Cloudflare sleepUntil](https://developers.cloudflare.com/workflows/build/sleeping-and-retrying/),
[Cloudflare Workflow limits](https://developers.cloudflare.com/workflows/reference/limits/),
[RunPod Pod management](https://docs.runpod.io/pods/manage-pods).


## Fim do lote sob supervisão

Com `terminalPubKey: null`, concluir o lote não desliga o Pod automaticamente.
Assim que os 20 resultados tiverem GET independente e verificação de integridade,
o operador autorizado usa **Stop**, não **Terminate**, e confirma que o Pod exato
ficou `EXITED`. O cutoff absoluto previamente armado fica como proteção caso a
parada manual não aconteça. Não armar outro emissor automático de STOP.

Para automatizar a parada antecipada, ainda é necessário ligar um coletor
independente dos 20 recibos a um assinante Ed25519 protegido e a um disparo
privado do Workflow terminal. Não fixe a chave de teste nem habilite o terminal
com base na declaração do Pod. A prova local `node --test terminal-workflow.test.mjs`
usa o Workflow e a barreira reais com adaptadores em memória: comprova a
sequência assinatura, claim persistido, POST único e GET `EXITED` simulado;
não é validação de desligamento no provedor nem do assinante operacional.
