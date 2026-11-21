# Piloto Docker local com Terraform

Esta pilha cria um único contêiner no Docker Desktop Linux do Windows. Usa
20 nós **lógicos** em um processo simulado, 5 rodadas, seed 0 e CPU. Não
executa LLM, não usa GPU, não publica portas, não monta pastas/socket, não lê
credenciais e roda sem rede. A imagem oficial do Python é fixada por digest.

A configuração fixa o named pipe do Docker Desktop. Antes de rodar, verifique
que o contexto `desktop-linux` corresponde a
`npipe:////./pipe/dockerDesktopLinuxEngine`. Use o Terraform 1.11.4 e o provider
`kreuzwerker/docker` 3.6.2. O limite numérico `cpu_period`/`cpu_quota` evita um
erro do provider 3.6.2 no parâmetro textual `cpus`.

Da pasta deste README, no PowerShell e com Terraform no PATH (ou invocando
diretamente o executável portátil verificado):

```powershell
$id = [guid]::NewGuid().ToString('N').Substring(0, 12)
$run = Join-Path $env:TEMP "tcc-local-docker-$id"
New-Item -ItemType Directory $run | Out-Null
$archive = Join-Path $run 'payload.zip'
$state = Join-Path $run 'local.tfstate'
$plan = Join-Path $run 'local.tfplan'
$image = 'docker.io/library/python@sha256:5e511b0e940def74dd23389510300c76017ca9bbc92484c40cff0951adf32245'
python -B prepare.py --archive $archive
terraform fmt -check
terraform init -backend=false -input=false
terraform validate
terraform plan -input=false -refresh=false "-state=$state" "-out=$plan" "-var=run_id=$id" "-var=archive=$archive" "-var=python_image=$image"
```

Confira o plano: somente `docker_image.python` e `docker_container.pilot`.
Aplique apenas esse plano salvo, então verifique o código de saída e o
recibo antes de declarar sucesso:

```powershell
terraform apply -input=false "-state=$state" $plan
$name = "tcc-n20-local-$id"
docker --context desktop-linux wait $name
docker --context desktop-linux logs $name
$artifacts = Join-Path $run 'artifacts'
New-Item -ItemType Directory $artifacts | Out-Null
docker --context desktop-linux cp "${name}:/tmp/tcc-output/." $artifacts
Get-Content (Join-Path $artifacts 'receipt.json')
```

O código do contêiner deve ser 0 e o recibo deve indicar 5 rodadas e 100/100
pares nó-rodada. `must_run=false` conserva o contêiner parado; `apply` por si
só não prova que o teste passou. Se decidir removê-lo, preserve primeiro
o recibo e as métricas; verifique nome, etiqueta `org.tcc.run-id` e o
plano de destruição desta execução, sem usar `docker prune`. Não adicionar
estado Terraform, ZIPs ou resultados ao Git.

## Simulacao M80 opcional, sem rede

Para reproduzir a simulacao de 50 rodadas no mesmo contêiner local, acrescente
--scenario m80 a prepare.py e gere novo ID, ZIP e estado. A simulacao usa seed 0,
16 nos anormais e dropouts com p=0,30, tres primeiras rodadas de genese sem
lider e auditoria aleatoria p=0,2. O replay do EMA simetrico usa as mesmas
respostas do EMA assimetrico. Esse piloto foi desenhado antes do C13 oficial:
a regra geral de omissao e semelhante, mas nao usa a mesma sequencia de
sorteios ou LLM. Nao e evidencia do servidor nem do Smol BF16.

Para gerar a figura local a partir das metricas copiadas, use Python com
Matplotlib e rode render_m80.py <diretorio-dos-artefatos>. O renderizador nao
substitui PNG ou SVG existentes. Os testes offline verificam os dois ZIPs
extraindo e executando sua logica Python, sem ligar Docker ou uma GPU:

    python -m unittest infra.runpod.n20.test_local_pilots

O comando acima deve ser executado em n20-runtime. Este Terraform continua
apontado somente ao Docker Desktop Linux local de Windows. Nao representa
um teste de um no Smol real; o unico conteiner simula 20 nos logicos.
