# Núcleo do diário warm incremental

O módulo `incremental_warm_journal.py` é deliberadamente isolado: não
inicia worker, não abre GPU, não invoca R2, não solicita STOP e não tem CLI.
O `Journal` deve viver fora do Pod, num diretório privado e gravável apenas
pelo controlador, com SQLite, lock e fsync. Esta API não instala essa
proteção, não recebe nem gera chaves privadas e não transforma a prova
atual do primeiro caso (`eligible_for_next_case: false`) em autorização.

Um instalador/operador independente deve pinçar o `BatchProtection` exato
(Pod, owner, datacenter, nome, UUID, commit, perfil, horários e orçamento),
versões do guard/Worker e os SHA-256 do DER de duas chaves públicas Ed25519:
(1) o autorizador de lease e (2) o verificador independente de GET. O
digest imutável de `Scope` inclui essas âncoras e a ordem oficial dos casos.
Não reusar um arquivo de diário com escopo diferente, nem implantar essa
API num host em que o Pod possa alterar a autoridade, o relógio ou os dados
SQLite. A prova de vida e a política de STOP permanecem fora deste módulo.

Chamadas pretendidas:

1. `first(envelope)`: registra só a primeira lease assinada e fresca, com
   cenário e UUID exatos, observação autenticada do guard por hash e prazo
   do caso limitado pelo cutoff. Não começa os processos.
2. `seal_active(run_id, sha256=..., size=...)`: chamada somente pelo
   validador independente do ZIP já selado. O tamanho e o hash são imutáveis.
3. `transition(get_envelope, next_lease)`: confere READBACK GET independente
   para objeto exato `tcc/prod/incremental-v1/n20-<run-id>.zip`, hash, bytes,
   arquivo verificado, 20 nós/50 rodadas/1.000 gerações e a assinatura de
   outra autoridade. Em uma transação, verifica que a próxima lease é
   do cenário imediatamente seguinte, carrega o digest desse mesmo GET,
   permanece sob o mesmo Pod e consome UUID novo. Falta, divergência,
   expiração ou corrida não concedem outro caso. Um caso aberto não é
   automaticamente relançado após queda do controlador.

Os envelopes são `evidence` mais `signature_ed25519_base64`; a assinatura
cobre `artifact_store.json_bytes(evidence)`. Os campos exatos estão em
`LEASE_FIELDS`/`GET_FIELDS` e o schema muda por função. Nem o primeiro recibo
produzido por `incremental_first_transfer` nem um fixture é aceito diretamente.
É necessário conectar um autorizador e um assinante independentes reais,
provar a montagem protegida e usar os leases autenticados no supervisor
resident; este núcleo não altera gates atuais e não é liberação de lote real.

Teste local: `python -B -m unittest infra.runpod.n20.test_incremental_warm_journal`.
Usa chaves efêmeras e relógio histórico de fixture para dois casos, testa
persistência, recusas e corrida, sem produzir credencial de operação.
