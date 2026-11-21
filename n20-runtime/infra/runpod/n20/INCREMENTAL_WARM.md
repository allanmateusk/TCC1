# Ensaio local da campanha incremental com residentes

Este ensaio usa o worker HTTP e o controle de cenários, mas **não habilita
produção**. São só os dois primeiros casos do perfil incremental, sequenciais,
20 nós e 50 rodadas cada. O modelo é um substituto de CPU explicitamente marcado;
os 20 processos residentes mantêm seus PIDs e carregam uma vez. Cada novo UUID
tem processos de protocolo, SQLite, reputação, auditoria e checkpoints próprios.
As amostras são contabilizadas por UUID, nó e semente; nenhum resultado é
reutilizado entre cenários.

Executar no diretório de runtime com as dependências de desenvolvimento já instaladas:

    python -B -m infra.runpod.n20.incremental_warm_smoke --output <diretorio-temporario-novo>

A prova rejeita memória livre inicial insuficiente, usa prazo e proteção de RAM,
registra o encerramento de processos e verifica se as portas locais voltaram a
ficar livres. Não monta ZIP, não carrega pesos, não usa Git, GPU, RunPod ou R2.
Os arquivos são marcados CPU_ONLY_NOT_PRODUCTION.

O seam usa callbacks distintos para PUT e GET: run_id, scenario_id, campaign_id,
profile_sha256, bucket, key, sha256, size e deadline vinculam ambos ao mesmo selo.
No ensaio, o armazenamento é só um diretório temporário separado. Um timeout de
PUT no primeiro caso é reconciliado por GET com o mesmo digest, sem repetir PUT.
Nenhum ACK libera o cenário seguinte. O comprovante sintético é incompatível
com o watchdog real. Falta ou divergência no GET não autoriza outro cenário.

O journal incremental sabe ordenar os 20 casos; o ensaio de worker cobre somente
dois deles. A entrada oficial do benchmark e o pool real recusam o incremental
sem qualificação. A futura operação exige lançamento Linux protegido com
qualificação BF16/VRAM real, controlador externo operacional com prazo e parada
confirmada, callbacks de transporte autorizados com credenciais independentes
e validação dos artefatos reais. O marcador exclusivo local desta prova não
substitui a trava de execução Linux nem habilita retomada oficial.
