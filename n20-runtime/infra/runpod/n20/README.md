# TCC: inferência distribuída ao vivo com 20 nós

Perfil isolado do experimento RunPod de 50 nós. O Terraform lê o mesmo perfil do
executor e faz um **plano local, sem provider nem recursos remotos**: apenas confere
a topologia, o modelo e o volume de trabalho. Não cria máquina nem altera a
campanha preexistente. Não é um plano de compra/provisionamento.

## Grade e inferência

| Cenário | Nós em conluio | Transformação |
| --- | ---: | --- |
| baseline | 0/20 | nenhuma |
| m20-alto | 4/20 | ruído multiplicativo forte |
| m40-alto | 8/20 | ruído multiplicativo forte |
| m80-alto | 16/20 | ruído multiplicativo forte |
| m40-sutil | 8/20 | distância relativa 0,2 |
| m80-sutil | 16/20 | distância relativa 0,2 |

Cada cenário usa 50 questões fixas do GSM8K e cinco sementes (0–4), um cenário e
uma semente por disparo, 1.000 gerações novas por execução. São 30 combinações
(30.000 gerações se toda a grade for solicitada separadamente). A auditoria
aleatória usa p=0,2 (probabilidade, não número fixo de auditorias); cinco rodadas
de teste ocorrem a cada 10 rodadas. A nota é exata, a topologia é 4-regular, com
medoide, orquestração dinâmica e EMA assimétrico (`ema_slow_up`).
Os nós em conluio se comportam como honestos nas cinco primeiras rodadas.
Com `knows_schedule` e auditoria aleatória, eles não veem quais rodadas foram auditadas.

O ruído forte já implementado no simulador é `s × (|b|+1) × 10^k`, com sinal
compartilhado `s∈{-1,+1}` e `k∈[3,6]`. Ele é aplicado à geração do mesmo nó
de referência do conluio: coordena a **resposta enviada**, sem pular a geração
local dos participantes. O controle sutil usa distância relativa 0,2 em
relação à base não nula. Não confundir estes dados sintéticos de consenso
com tráfego real.

Cada nó tem próprio processo, endpoint local, geração, semente, instância **SmolLM3-3B NF4** e cópia residente em CUDA. Os processos compartilham só o snapshot
fixado em disco, não um serviço central de inferência. São dez instâncias por GPU
em duas GPUs como topologia de referência. Não herda uma estimativa de VRAM do
Qwen. Antes de habilitar, meça num próximo teste controlado no próprio servidor
o pico por processo (incluindo alocação CUDA total, prompt representativo e
geração no limite), informe-o em GiB e confirme capacidade com o smoke concorrente.
O pré-requisito de VRAM livre é esse pico medido × 10 processos × 1,2 de folga por
GPU. A capacidade e o tempo dos 20 processos juntos ainda precisam ser medidos.
O checkpoint oficial é fixado em `profile.json`; usa o chat template do SmolLM3
com `/no_think`, sem alterar o prompt usado pelo Qwen legado.

O arquivo de entrada `gsm8k_test_n20.json` contém exclusivamente as mesmas
50 perguntas, IDs e gabaritos do GSM8K, sem respostas pré-geradas. Cada cenário inicia
com diretório obrigatório novo e sem registros de inferência. O SQLite por nó
registra as novas gerações e deduplica somente a mesma solicitação em caso de
repetição técnica ou da consulta pelo nó em conluio; não há replay entre
cenários/rodadas/execuções, nem fallback para banco. A validação exige uma
geração nova única em cada nó × rodada (1.000/1.000), as 50 rodadas completas e
coerência das respostas finais com as métricas. A configuração reaproveita o
worker e o `/health` da Lara (commit `58f1f998f707ea484ab83370802c663baea18d82`),
verificando identidade, uma instância ativa e NF4 antes da coordenação.
As chamadas têm limite configurado de 600 s no protocolo; a carga de cada nó
tem limite de 5 min. O processo supervisor termina os nós ao concluir/falhar.

## Preflight e execução

Na pasta `n20-runtime`, em ambiente com as dependências node/orchestrator:

```sh
python -m infra.runpod.n20.benchmark preflight
python -m unittest infra.runpod.n20.test_benchmark sistema.tests.test_dedicated_inference sistema.tests.test_dedicated_orchestrator sistema.tests.test_runner_per_node
terraform -chdir=infra/runpod/n20 init -backend=false
terraform -chdir=infra/runpod/n20 validate
terraform -chdir=infra/runpod/n20 plan -refresh=false
```

O push nesta branch só permite teste estático/mocado sem chaves ou GPU.
A execução real do novo workflow exige disparo manual, `acknowledge_live`,
`TCC_LIVE_N20_ENABLED=true`, ambiente `tcc-live-n20` e runner Linux exclusivo
com o label `tcc-n20-cuda`. Antes de habilitar, configure revisores obrigatórios
e restrição da branch no ambiente GitHub. Instale as dependências de execução,
inclusive PyTorch CUDA e as de `sistema/node/requirements-dedicated.txt`, no runner
existente, configure `TCC_LIVE_N20_SNAPSHOT` com o snapshot local fixado pelo
perfil e deixe os endpoints 18100–18119 livres. Configure também
`TCC_LIVE_N20_PEAK_VRAM_PER_NODE_GIB` com o maior pico medido no runner. O workflow guarda artefatos
inclusive em falhas, tenta interromper com limite interno de 110 minutos e
aplica limite do job de 120 minutos. Não usa segredos de alocação nem comandos
`terraform apply`.

GitHub só oferece `workflow_dispatch` se o arquivo do workflow existir também
na branch padrão. Até isso ser aprovado e publicado lá, o GitHub executa o
preflight no push; para execução ao vivo, após aprovação, use a CLI no próprio
runner com o mesmo perfil:

```sh
TCC_LIVE_N20_APPROVED=true TCC_LIVE_N20_PEAK_VRAM_PER_NODE_GIB="$PICO_MEDIDO_GIB" python -m infra.runpod.n20.benchmark run \
  --scenario m80-alto --seed 0 --snapshot "$TCC_LIVE_N20_SNAPSHOT" \
  --output /caminho/novo/live-n20-m80-alto-s0
```

O workflow antigo do projeto de origem não foi copiado. Para
provisionar N20 mais tarde, é necessário validar uma imagem compatível com
este executor e projetar seu próprio perfil de Controller/RunPod, verificação
de capacidade, custo, prazo, upload e encerramento automático. Nenhum GPU
ou serviço pago foi ativado por esta configuração.

## Teste local sem subir resultados

```sh
python -m infra.runpod.n20.integration_smoke run --output /caminho/novo/smoke-local
```

O smoke percorre baseline e m80-alto (50 rodadas cada) com os endpoints, o
supervisor e a coordenação reais, substituindo apenas o gerador por um modelo
de teste. Verifica as 1.000 gerações por cenário, a perturbação, as cadeias
e o fechamento dos processos/portas. Saídas de teste ficam locais e fora do
Git e não contam como resultados de produção.

## Checklist antes do servidor: resultados e desligamento

**Hoje:** o supervisor encerra seus processos de nós e orquestrador, inclusive
em erro. O limite do job não garante desligamento do host/GPU. O workflow
real, se habilitado, guarda artefatos no GitHub; não envia ao S3 e não encerra
ou provisiona o servidor. A campanha legada RunPod/R2 não é compatível com
este perfil. Não reutilize o controlador legado como se validasse o N20.

**Antes de habilitar produção:**

1. Configurar um bucket privado S3, com criptografia, política de retenção,
   permissão mínima para o prefixo de cada execução e credenciais da função
   do servidor, não segredos no Git. A máquina deve poder se conectar ao S3.
2. Persistir status e checkpoints parciais em armazenamento durável durante
   o experimento. Enviar arquivos de produção ao prefixo único do run,
   incluindo métricas, logs necessários, proveniência (commit, snapshot,
   semente, cenário e versões), manifesto e SHA-256. Verificar tamanho,
   checksum e presença dos objetos; só marcar o run como final após conferir.
3. Implementar um supervisor externo à máquina e ao runner do GitHub,
   responsável pelo prazo, por encerrar alocação de GPU no sucesso ou falha e
   por reconciliar execuções órfãs. Guardar logs parciais diante de falha,
   tentar upload por intervalo limitado e encerrar mesmo se o S3 ficar
   indisponível; nunca manter a GPU ligada indefinidamente.
4. Validar em um smoke no servidor, incluindo falha simulada de upload e
   confirmação das duas fases: arquivo verificado no S3 e alocação encerrada
   no provedor. Não promover resultados de testes locais a produção.
