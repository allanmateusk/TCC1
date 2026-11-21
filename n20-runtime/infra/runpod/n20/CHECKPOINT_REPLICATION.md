# Replicação offline de checkpoints do piloto N20

A réplica por rodada empacota o checkpoint concluído e toda a cadeia de
checkpoints anterior, os prefixos dos seis logs, a configuração com identidade
e os 20 backups SQLite. Usa a API SQLite Backup em leitura, não copia WAL
ativo, e elimina linhas posteriores somente na cópia. A reconstrução abre
o backup com verificação de integridade SQLite, confere identidade, tarefa,
semente e resposta, e reaplica os ledgers sem rodar inferência.

`RoundReplication` usa um catálogo protegido separado da pasta primária e uma
interface de armazenamento com PUT exclusivo e GET. Antes do PUT, grava o ZIP
imutável e seu digest esperado. O recuo autorizado é a última rodada contígua
cujo GET foi baixado e validado independentemente. PUT/GET com erro ou conteúdo
alterado não publica recibo e bloqueia a próxima rodada. A tentativa seguinte
usa o ZIP já preparado, não gera outra cópia ou novas respostas. A restauração
requer armazenamento, catálogo protegido e diretório vazio, não o workspace
primário. A restauração não inicia processos.

O adaptador fornecido é somente uma segunda pasta local. O teste reaproveita o
piloto HTTP sintético de 20 nós, sem Docker, GPU, rede ou credenciais:
`python -B -m infra.runpod.n20.checkpoint_replication_smoke --source <piloto-http-sintetico> --output <nova-pasta-temporaria>`.

Limites: o backup exige que os escritores tenham encerrado a rodada e estejam
sob o mesmo controle exclusivo, sem corrida para a próxima rodada; não
estabelece isolação transacional entre os 20 bancos. A chave é única por
execução/rodada e o catálogo deve estar em domínio de falha independente antes
de uso real. Os bancos de retomada incluem saídas cruas e exigem autorização,
classificação, acesso privado, retenção e separação dos ZIPs finais antes de
qualquer envio a R2 real. Este módulo não integra o orquestrador em produção,
não conecta R2, não substitui fencing e não habilita retomada automática.

O formato atual exige UUID externo nos bancos e uma intenção correspondente a cada geração confirmada. Uma intenção sem resultado confirmado, mesmo em rodada futura, bloqueia a cópia. O padrão também bloqueia um banco que avançou além da fronteira: só o fixture histórico usa replay_fixture para recortar uma cópia já atestada.