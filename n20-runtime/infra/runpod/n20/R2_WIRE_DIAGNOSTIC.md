# Teste do transporte R2 do lote, sem GPU

Este teste **não é o smoke anterior**: usa o mesmo abridor TLS sem proxy ou
redirecionamento, o mesmo journal durável de PUT (abertura exclusiva,
fsync, condição `If-None-Match: *` e nenhum novo PUT em caso ambíguo) e o
mesmo GET limitado que o transporte incremental usa. Há dois processos/
concessões distintos: um PUT e um GET. Ambos existem em memória apenas.

Somente um TXT pequeno e sintético é permitido. A chave exclusiva é
`tcc/piloto/diag-warm-<id>.txt` no bucket privado `tcc`. Não usa ou aceita
namespace de produção, ZIP, recibo oficial, cenário ou API do controlador.
A única prova positiva é `verified_diagnostic_only` (SHA-256 e bytes
confirmados pelo GET). Não abre link público, não apaga ou sobrescreve nada.

PowerShell interativo no Windows, apenas após aprovação do teste real:

    Set-Location 'C:\Users\allan.souza_allugato\TCC1-incremental-revisao\n20-runtime'
    $py = 'C:\Faculdade\TCC1\.venv-llm\Scripts\python.exe'
    $cfg = 'C:\Faculdade\TCC1-n20-personal\n20-runtime\infra\runpod\n20\r2-pilot.local.json'
    $work = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('Temp\tcc-wire-' + [Guid]::NewGuid().ToString('N'))
    & $py -B -m infra.runpod.n20.r2_wire_diagnostic prepare --config $cfg --work $work
    & $py -B -m infra.runpod.n20.r2_wire_diagnostic put --config $cfg --work $work
    & $py -B -m infra.runpod.n20.r2_wire_diagnostic get --config $cfg --work $work

O config só pode conter endpoint oficial R2, bucket tcc, região auto e prefixo
tcc/piloto, sem nenhuma credencial. Se usar outro PowerShell para GET,
reutilize a mesma pasta absoluta `$work`. O GET é mais representativo
quando um verificador em processo separado usa sua própria chave de leitura
do bucket (chave distinta da do PUT). Os Access Key ID/Secret Access Key
são solicitados por papel, ocultos no terminal, nunca em chat, config, args
ou logs. O preparo não usa rede. O diagnóstico expira em quinze minutos
e cada URL gerada tem no máximo cinco minutos. PUT bem-sucedido ou
incerto não prova nada; nunca repita o PUT após uma tentativa. GET pode
reconciliar a tentativa sem carregar chave/URL do PUT.

O teste qualifica só comunicação com o R2 privado, método separado, proteção
de criação, persistência da intenção e comparação do readback. Não valida
arquivo BF16 oficial, assinatura de publicação/autorização do cenário, canal
Linux/Pod, avanço, GPU ou parada. Os testes automatizados usam chaves fake
e HTTP em memória; executar apenas os testes não envia objeto.
