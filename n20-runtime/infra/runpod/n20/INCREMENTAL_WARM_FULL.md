# Linux warm: 20 casos numa alocação

`incremental_warm_live.supervise_full_campaign()` é separado da qualificação
curta. É um callable sem CLI pública e fechado sem autorização protegida:
`warm-resident-release.json` deve ter schema `tcc-qualified-full-residency/v1`,
`Scope.mode=official-full`, plano longo de 4–7 h, guard/versão/Pod fixos e
leases assinadas por controle externo. A política curta só abre dois casos
e o lote não aceita a prova curta como substituta da aprovação longa.

O mesmo `ResidentPool` existe desde o primeiro cenário até o último
ou fail-closed. Cada cenário usa UUID, bancos, processos de protocolo,
reputação e checkpoints próprios. O runtime reabre o ZIP selado e exige
SHA/tamanho do GET independente, cada vez com a release do diário
assinada após commit. Os arquivos de handoff protegidos são
`warm-transition-02.json` a `warm-transition-20.json` (número 1-based do
caso de destino). O runtime não consulta o SQLite gravável do controlador
nem cria suas próprias autorizações. Invalidez, expiração, arquivo ausente
até o cutoff ou troca de Pod impede avanço. As primeiras duas execuções
são os primeiros gates dessa mesma alocação, e não exigem desligar o Pod.

O worker fecha os residentes depois do ZIP final. O resultado então diz
`last_independent_get_verified:false`: o controlador externo ainda deve
confirmar o último GET. Nenhum #21 é admitido. O encerramento de processos
locais não pede STOP do Pod nem confirma estado do provedor; o mecanismo
externo único é responsável pela parada, com fallback manual.
A execução comum, disponibilidade/driver BF16 real, instalação protegida,
canal externo de R2 e prova de execução dos 20 ainda devem ser qualificados.
