# Supervisor Linux warm incremental (dois casos, fechado por padrão)

`incremental_warm_live.supervise_two_cases()` é um callable isolado, não um
comando de lançamento. Não cria recursos, não chama RunPod ou R2 e não
aproveita as flags antigas. O primeiro caso usa a admissão assinada já
existente do primeiro executor. A fila/diário independente nunca deve ficar
gravável pelo Pod. O segundo caso só passa após o commit desse diário.

O instalador independente precisa usar os mesmos arquivos protegidos do
primeiro caso, e em `/etc/tcc-n20-incremental` acrescentar:

- `warm-resident-release.json`: schema `tcc-qualified-two-case-residency/v1`,
  `scope` com `Scope` + `BatchProtection` completos, o
  `approved_scope_sha256` e `qualifier_report_sha256` da validação real
  independente de residentes. Não copiar hash ou configuração de fixture.
- `warm-lease-ed25519.pem`, `warm-get-ed25519.pem`: somente duas chaves
  públicas independentes, DER/SHA conferidos com as âncoras do escopo.
- `warm-first-lease.json`: primeira lease curta autenticada, do mesmo run
  e hash da observação de lançamento.
- `warm-next-transition.json`: handoff posterior ao GET oficial, contendo
  `readback`, `next_lease` e `committed`, todos assinados. O último
  usa o schema `tcc-warm-controller-committed-transition/v1` e vincula o
  commit independente do diário aos hashes exatos dos outros dois envelopes.
  O envio protegido só deve acontecer após `Journal.transition` confirmado.
- Um marcador externo protegido `cancel-warm-batch` apenas impede novos
  trabalhos ou pede encerramento local; nunca concede outra lease.

A rotina preflight preserva snapshot/commit, BF16/KV e capacidade GPU.
Em cada caso, usa a execução e o finalizador oficiais, cria UUID e
SQLite distintos e preserva o ZIP local. O sinalizador de instalação
não substitui verificações de assinatura, identidade, validade e orçamento.
O Pod reabre a primeira cópia local e compara bytes e SHA aos valores do
GET independente antes de permitir que o mesmo pool abra o segundo caso.
Sem relay ou após a janela, não há segunda execução. Depois do segundo
caso, encerra os processos, sem terceiro caso, retomada, PUT, GET ou
afirmação de STOP dentro desta rotina.

Prova: testes unitários reprovam recibos ausentes, digests, bytes e assinatura
alterados, além de env/Windows sem trust. A integração CPU/localhost usa a
mesma validação de relay com o worker, 20 residentes e duas ondas reais de
protocolo, mas não instala os arquivos Linux de produção, não usa GPUs, não
emite autorização real, nem verifica o GET final no R2. A ligação do
canal protegido, credenciais e qualificação GPU/avisos/STOP é um passo
operacional separado.
