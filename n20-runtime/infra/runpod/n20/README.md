# TCC: inferência distribuída ao vivo com 20 nós

Perfil isolado do experimento RunPod de 50 nós. O Terraform lê o mesmo perfil do
executor e faz um **plano local, sem provider nem recursos remotos**: apenas confere
a topologia, o modelo e o volume de trabalho. Não cria máquina nem altera a
campanha preexistente. Não é um plano de compra/provisionamento.

## Grade oficial: 17 cenarios e um piloto separado

Execute os cenarios na ordem registrada em profile.json. Todos usam seed 0,
20 nos, 50 rodadas e as mesmas questoes, em igual ordem. O piloto tem 20 nos
honestos e 5 rodadas, com p=0,2 e sem genese. Sao 17.000 geracoes oficiais,
mais 100 do piloto. Um disparo executa um cenario; nao ha disparo automatico
em lote, cobranca, provisionamento ou envio automatico de resultados.

| Ordem | ID | Conluio | Auditoria | Mudanca adicional |
| ---: | --- | ---: | --- | --- |
| 1 | C01 | 0% | nenhuma | controle |
| 2 | C16 | 20% | nenhuma | |
| 3 | C17 | 40% | nenhuma | |
| 4 | C10 | 60% | nenhuma | |
| 5 | C14 | 80% | nenhuma | |
| 6 | C11 | 60% | fixa | mesmo numero planejado de C08 |
| 7 | C02 | 40% | p=0,1 | |
| 8 | C03 | 40% | p=0,2 | |
| 9 | C08 | 60% | p=0,2 | |
| 10 | C04 | 80% | p=0,1 | |
| 11 | C05 | 80% | p=0,2 | |
| 12 | C09 | 60% | p=0,2 | genese 1-3 |
| 13 | C06 | 80% | p=0,2 | genese 1-3 |
| 14 | C07 | 80% | p=0,2 | nota gradual |
| 15 | C12 | 60% | p=0,2 | EMA simetrico |
| 16 | C15 | 80% | p=0,2 | EMA simetrico |
| 17 | C13 | 80% | p=0,2 | genese 1-3 e omissao sintetica pela coorte de 16 |

Padrao: topologia 4-regular, orquestracao dinamica, medoide, nota exata e
EMA assimetrico (ema_slow_up). Nas primeiras cinco rodadas os conluiados
nao perturbam suas respostas. A partir da sexta, todos os conluiados usam
o valor-base do mesmo membro, enquanto cada no ainda gera seu proprio valor
na GPU. A transformacao multiplicativa oficial usa
s * (abs(base)+1) * 10^k, sinal compartilhado e k uniforme em [3,6].

Os testes fixos nas rodadas 10/20/30/40/50 sao de avaliacao, nao aplicam
gabarito ao protocolo. Para auditoria aleatoria, cada rodada recebe o mesmo
U em todos os cenarios, pela seed 0, mesmo se for inelegivel. Os testes e a
genese sao excluidos, sem deslocar o sorteio das demais rodadas. Assim,
p=0,1 e subconjunto de p=0,2, e habilitar a genese nao rerrola a agenda.
C11 espalha deterministicamente nas rodadas elegiveis tantos pontos fixos
quanto os sorteados em C08. O atacante nao adapta sua conduta a agenda em
C11: o comparativo altera apenas a agenda. Para listar um plano sem rodar,
use python -m infra.runpod.n20.benchmark plan [--scenario C13].

Genese significa que as rodadas 1 a 3 dispensam eleicao, proposta e voto.
Cada no gera sua resposta, um registro de calibracao com gabarito e
gravado em cada replica e o coordenador confirma o mesmo hash nas 20.
A auditoria aleatoria e uma correcao externa por gabarito, distinta do
auditor eleito e do quorum da proposta. O perfil all mantem bypass do
quorum da correcao; um bloqueio nao e esperado nessa configuracao.
audit-events.jsonl registra por rodada o planejado/preemptado, genese,
aplicado/bloqueado/stale/inalcancavel por no, e omissoes intencionais.
O evento completo e emitido depois de gravar todas as metricas da rodada.

Em C13, cada um de node-0..node-15 tem probabilidade 0,30 de omitir
a resposta submetida em cada rodada, inclusive na genese, em agenda
independente e reproduzivel. Reproduz a mesma regra de coorte do piloto
local (nao a mesma sequencia antiga de pares no/rodada). Mesmo o no com
omissao gera a resposta crua na GPU, ainda vota no protocolo e pode
fornecer sua base crua ao conluio. Falha de rede/processo e saida sem
numero nao sao classificadas como omissao programada.

Cada nó tem próprio processo, endpoint local, geração, semente, instância **SmolLM3-3B BF16 sem quantização** e cópia residente em CUDA. Os processos compartilham só o snapshot
fixado em disco, não um serviço central de inferência. São dez instâncias por GPU
em duas GPUs como topologia de referência. Não herda uma estimativa de VRAM do
Qwen. Antes de habilitar, meça num próximo teste controlado no próprio servidor
o pico por processo (incluindo alocação CUDA total, prompt representativo e
geração no limite), informe-o em GiB e confirme capacidade com o smoke concorrente.
O pré-requisito de VRAM livre é esse pico medido × 10 processos × 1,2 de folga por
GPU. A capacidade e o tempo dos 20 processos juntos ainda precisam ser medidos.
O checkpoint oficial é fixado em `profile.json`. O carregador exige suporte
nativo à BF16, verifica o dtype real e a ausência de quantização, e aborta em vez
de substituir por FP16, NF4 ou CPU. Os pesos somam 5,73 GiB por processo antes
da memória de execução; o preflight não certifica a capacidade da máquina.
O modelo usa o chat template do SmolLM3
com `/no_think`, sem alterar o prompt usado pelo Qwen legado.

O arquivo de entrada `gsm8k_test_n20.json` contém exclusivamente as mesmas
50 perguntas, IDs e gabaritos do GSM8K, sem respostas pré-geradas. Cada cenário inicia
com diretório obrigatório novo e sem registros de inferência. O SQLite por nó
registra as novas gerações e deduplica somente a mesma solicitação em caso de
repetição técnica ou da consulta pelo nó em conluio; não há replay entre
cenários/rodadas/execuções, nem fallback para banco. A validação exige uma
geração nova única em cada nó × rodada, as rodadas declaradas completas e
coerência das respostas finais com as métricas. A configuração reaproveita o
worker e o `/health` da Lara (commit `58f1f998f707ea484ab83370802c663baea18d82`),
verificando identidade, uma instância ativa e BF16 sem quantização antes da coordenação.
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
`TCC_LIVE_N20_PEAK_VRAM_PER_NODE_GIB` com o maior pico medido no runner. O workflow deixa os artefatos no runner, sem envio automatico. Tenta
interromper com limite interno de 110 minutos e
aplica limite do job de 120 minutos. Não usa segredos de alocação nem comandos
`terraform apply`.

GitHub só oferece `workflow_dispatch` se o arquivo do workflow existir também
na branch padrão. Até isso ser aprovado e publicado lá, o GitHub executa o
preflight no push; para execução ao vivo, após aprovação, use a CLI no próprio
runner com o mesmo perfil:

```sh
TCC_LIVE_N20_APPROVED=true TCC_LIVE_N20_PEAK_VRAM_PER_NODE_GIB="$PICO_MEDIDO_GIB" python -m infra.runpod.n20.benchmark run \
  --scenario C05 --seed 0 --snapshot "$TCC_LIVE_N20_SNAPSHOT" \
  --output /caminho/novo/live-n20-C05-s0
```

O workflow antigo do projeto de origem não foi copiado. Para
provisionar N20 mais tarde, é necessário validar uma imagem compatível com
este executor e projetar seu próprio perfil de Controller/RunPod, verificação
de capacidade, custo, prazo, upload e encerramento automático. Nenhum GPU
ou serviço pago foi ativado por esta configuração.

## Primeiro piloto: 20 nos honestos por 5 rodadas

Execute uma combinacao por vez. Com capacidade validada e autorizacao do
runner ja existente:

\`\`\`sh
TCC_LIVE_N20_APPROVED=true TCC_LIVE_N20_PEAK_VRAM_PER_NODE_GIB="$PICO_MEDIDO_GIB" python -m infra.runpod.n20.benchmark run \
  --scenario pilot --seed 0 --snapshot "$TCC_LIVE_N20_SNAPSHOT" \
  --output /caminho/novo/piloto-n20-r5-s0
\`\`\`

O manifesto separa pilot de official. O smoke sem GPU exercita HTTP e
protocolo com um modelo substituto; nao e evidencia de inferencia BF16,
capacidade do servidor, nem robustez do protocolo oficial.

## Teste local sem subir resultados

```sh
python -m infra.runpod.n20.integration_smoke run --output /caminho/novo/smoke-local
```

O smoke executa o piloto honesto (100 geracoes) e C13 (1.000 geracoes),
com endpoints e protocolo reais e um modelo substituto, sem CUDA.
Verifica agenda, registros de genese, omissoes apos geracao, cadeias,
metricas e fechamento dos processos/portas. Nenhum resultado vai ao Git.

## Checklist antes do servidor: resultados e desligamento

**Hoje:** o supervisor encerra seus processos, inclusive em erro; isso
nao encerra a alocacao do host. Nao ha upload automatico ao GitHub nem S3.
Um teste local isolado de um modelo com adaptador temporario de leitura dos
pesos nao qualifica a imagem Linux nem a capacidade dos 20 nos concorrentes.
A campanha legada RunPod/R2 nao e compativel com este perfil.

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
