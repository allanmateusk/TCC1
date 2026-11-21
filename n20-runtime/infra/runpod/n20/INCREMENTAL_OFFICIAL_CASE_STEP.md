# Passo externo supervisionado por cenário do lote oficial

No controlador Windows/Linux, independentes do Pod, use
`incremental_official_case_step.CaseStep`, depois de `Controller.first` e
da instalação protegida inicial. Não liga, não para e não lança nenhum Pod.
Uma chamada `execute(write_role=...,read_role=...,cf_read_token=...,
pod_read_token=...,next_run_id=...)` trata o caso ativo inteiro:
cópia autenticada do ZIP, lacre, observação fresca, emissão segregada de PUT e
GET, envio do grant ao Pod, GET independente e relay do próximo caso. Para
o #20, passe `next_run_id=None`; o comprovante final fica no controlador.
Para uma instalação do relay com resposta incerta, use
`deliver_existing(index=<índice exato>)` com o mesmo conteúdo, sem reemitir
lease ou rodar nada. Falha de PUT é reconciliada por GET do mesmo objeto;
não autoriza novo PUT, novo UUID ou novo cenário.

## Handoff operacional que ainda precisa ser instalado e qualificado

- O cliente OpenSSH é restrito a um host/porta/usuário, escopo/Pod e arquivo
  conhecido com **uma chave de host Ed25519 previamente verificada**. O SHA-256
  do JSON canônico `{schema: BRIDGE, scope_sha256, resource_id, host, port,
  user, known_hosts_sha256}` deve vir de aprovação independente. Não use
  TOFU, aceite automático, senha, agent forwarding, nem host emprestado.
- Instale do outro lado um usuário/serviço SSH restrito ao único comando
  `tcc-official-case-bridge`; não aceite shell geral. Um canal SSH recebe
  JSON canônico por stdin com `schema: tcc-official-ssh-controller-bridge/v1`,
  `scope_sha256`, `resource_id`, `run_id`, `operation`:
  - `fetch_archive`: responda somente os bytes do ZIP já final e imutável
    daquele UUID sob volume aprovado; máximo `artifact_store.MAX_ZIP`;
    contenha symlinks e qualquer path controlado pelo workload.
  - `send_put`: campo `frame` exato com `put_envelope`, `put_url`.
    Encaminhe em um único JSON compacto + LF para o descritor anônimo do
    supervisor `--publish-fd`. Não grave URL em arquivo ou log. Responda
    `QUEUED\n` apenas depois do enqueue; nem isso nem HTTP ACK provam PUT.
  - `install_relay`: campos `index` (1–19) e `relay`; confirme scope e as
    três assinaturas antes de instalar root-owned em
    `warm-transition-<index+1:02d>.json`, modo 0440, via arquivo exclusivo.
    Uma segunda entrega é aceitável somente se os bytes já instalados
    forem idênticos; responda com SHA-256 dos bytes reread + LF. Nunca
    sobrescreva outro conteúdo, nunca exponha escritor privilegiado ao Pod.
- Use dois clientes R2 distintos, o primeiro com mínima escrita necessária
  apenas no bucket exato, o segundo somente leitura. A interface recebe
  credenciais já fornecidas por armazenamento autorizado, em memória; não
  as lê do ambiente/argv, não grava valores e não fornece CLI com segredo.
  O Pod recebe apenas uma URL PUT condicional curta. A chave de assinatura
  de publicação Ed25519 continua fora do Pod. Veja o [OpenSSH manual]
  (https://man.openbsd.org/ssh_config).

Este passo foi exercitado localmente com SSH/HTTPS simulados e chaves
efêmeras, não com Pod real. Antes de Start, além do teste real R2 apartado,
ainda instale/qualifique o serviço do lado Linux com privilégios mínimos,
comprove a identidade SSH/autenticação, o guard e o hardware disponível.
Use o cutoff externo e a parada manual do Pod exato após o último GET
confirmado; nada nesta camada chama STOP.
