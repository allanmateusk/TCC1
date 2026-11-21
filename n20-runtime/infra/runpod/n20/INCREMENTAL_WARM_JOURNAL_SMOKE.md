# Ensaio integrado: diário assinado e residentes warm (somente CPU)

A prova usa o mesmo runner HTTP existente, 20 processos residentes de CPU,
a fila de simulação e o diário de transição autenticada. O adaptador de teste
não altera os gates reais. A versão válida executa os dois primeiros casos,
50 rodadas por caso. Os mesmos 20 PIDs permanecem carregados, mas cada caso
tem UUID, SQLite, reputação e checkpoints próprios.

No caso 1, são selados bytes JSON sintéticos com a prova do worker, trace de
auditoria, métricas e contagem. O diretório de objeto é separado. A leitura
reabre os bytes, verifica tamanho/SHA e estrutura e os confronta com a prova
do worker. O diário só registra o caso 2 após validar uma assinatura de
GET do verificador e o lease exato de outra chave. Um arquivo corrompido ou
ausente não produz assinatura, não muda o diário e não deixa sair uma
segunda onda nem os residentes abertos.

No diretório de runtime, com dependências HTTP existentes e OpenSSL já
instalado, rode uma modalidade de cada vez com caminho temporário novo:

    python -B -m infra.runpod.n20.incremental_warm_journal_smoke --mode valid --output <novo-diretorio>
    python -B -m infra.runpod.n20.incremental_warm_journal_smoke --mode missing --output <novo-diretorio>
    python -B -m infra.runpod.n20.incremental_warm_journal_smoke --mode corrupt --output <novo-diretorio>

É uma integração local (localhost e diretórios privados temporários), sem
GPU, modelo real, R2, Cloudflare, RunPod, ZIP oficial ou capacidade de
admissão. O relógio histórico e as chaves descartáveis mantêm os envelopes
sem valor de operação. A prova física de produção ainda requer supervisor
Linux, observador/issuer de lease, verificador R2 independente e credenciais
restritas, todos ligados aos gates existentes e ao cutoff externo.
