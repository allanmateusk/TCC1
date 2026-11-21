# Observador externo do primeiro caso incremental

Este adaptador não provisiona nem modifica recursos, não instala as âncoras
Linux e não oferece CLI. Precisa rodar apenas no controlador independente,
nunca no Pod. O único cenário que admite é `e4-c0-m00-p10-exact-u00-s0`.
O código do guard continua desarmado no checkout, com `APPROVED=null`.

## Interfaces e fontes autenticadas

- No plano aprovado fora do Git, fixe como bytes exatos, via SHA-256 obtido
  independentemente: `schema: "tcc-incremental-first-observer-approved/v1"`,
  `linux_trust` com o conjunto `incremental_first_live.TRUST_KEYS`,
  `run_id`, `worker_deployment_id`, `observer_spki_sha256` (SHA-256 do
  DER/SPKI da chave pública Ed25519) e `terminal_pub_key: null`.
  O primeiro caso não pode afirmar que os 20 casos terminaram.
- `collect_and_sign(...)` recebe o plano protegido, o pin externo, dois tokens
  transitórios de leitura obtidos pelo controlador, o caminho da chave
  privada já protegida e um OpenSSL instalado de confiança. Nunca salve os
  tokens no plano ou nos logs. Use permissões de leitura do Workers/Workflows
  na conta exata e `account:read` / `pods:read` na conta RunPod.
  O provisionamento e a validação da ACL NTFS não são feitos por este módulo.
- Somente GET por HTTPS: Cloudflare Workflow, versão, deployment
  (identificação exata e um único Worker 100%), saída integral da etapa
  `bind-exact-batch-1` e instância exata. O deployment consultado pelo ID
  prova o rollout fixado, não uma afirmação de que nenhuma outra versão foi
  publicada depois. A associação com a instância vem do ID da versão
  Workflow e, de forma separada, da versão do Worker capturada na saída por
  `CF_VERSION_METADATA.id`. Não se deduz a versão a partir do nome.
- RunPod: GET `/v2/account` seguido de GET do Pod exato, com owner,
  datacenter, nome e horário real de start fixados, Secure Cloud, RUNNING e
  opção STOP. Nenhuma configuração, e-mail ou ambiente do Pod vai para a
  evidência. A observação só assina se o Cloudflare mostrar o plano
  idêntico, armamento nos cinco primeiros minutos e sleep ainda pendente no
  UTC aprovado, com o estado recentemente reconsultado.
- O retorno é o envelope v2 assinado no formato aceito pelo Linux
  (`artifact_store.json_bytes` sobre evidence); não grava arquivo e não
  envia ao Pod. O controlador deverá entregá-lo apenas por canal
  autenticado a um instalador separado, protegido do executor Linux; o
  gate rejeita chaves ou envelopes colocados pelo executor, expirados ou
  divergentes. Não entregue a chave privada ou os tokens ao Linux.
  Se a API não fornecer os parâmetros, a saída integral e o sleep no
  formato exigido, não assine e não inicie inferência.

## Estado

Validado localmente com HTTP simulado e chave de teste transitória. O
deployment, a instância no Cloudflare, a leitura autenticada real no RunPod,
a entrega protegida e o STOP/EXITED continuam sem qualificação nesta versão.
Antes de qualquer Pod pago, verificar a serialização hospedada e o binding
de versão em Workflow disarmado para provedores. Não confundir GET-only com
nenhum efeito externo: o primeiro uso com tokens ainda deve ser autorizado.

Referências oficiais: [GET Workflow](https://developers.cloudflare.com/api/resources/workflows/methods/get/),
[GET deployment](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/deployments/methods/get/),
[GET instância](https://developers.cloudflare.com/api/resources/workflows/subresources/instances/methods/get/),
[GET resultado da etapa](https://developers.cloudflare.com/api/resources/workflows/subresources/instances/methods/step/),
[binding de metadados do Worker](https://developers.cloudflare.com/workers/runtime-apis/bindings/version-metadata/),
[GET conta RunPod](https://docs.runpod.io/api-reference-v2/account/get-your-account),
[GET Pod](https://docs.runpod.io/api-reference-v2/pods/get-a-pod).
