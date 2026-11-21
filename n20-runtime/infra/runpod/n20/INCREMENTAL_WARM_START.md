# Inicialização protegida do lote warm (Linux)

A entrada oficial é `infra.runpod.n20.incremental_warm_start`, executada no
mesmo ambiente do runner e no checkout Git limpo, root-owned, com SHA
exato pinado na observação assinada. Não use a CLI legado, flags de ambiente,
cópia de piloto, chave privada ou recibo de fixture para liberar o lote.

Antes de pagar/start, o operador deve preparar o release, a conta/transferência
SSH autenticada e o supervisor **independente** (fora do usuário do Pod):
cutoff Cloudflare longo 4–7 h com confirmação de armamento em até 5 min,
trust durável, um canal privado de recebimento de PUT e instalador de relays.
Ainda não são provisionados por este código. Verificar também volume de
rede, capacidade necessária, preço e fallback manual Stop/EXITED.

**Entrada Linux, somente depois do Start aprovado e do cutoff comprovado:**

1. Fora do Pod, o controlador registra o primeiro lease e emite
   `{observation,first_lease}`. O instalador autorizado coloca em
   `/etc/tcc-n20-incremental` o config/PEM Linux, o handoff Ed25519, a policy
   full e as chaves públicas de lease/GET já documentadas. Esses arquivos
   e os pais devem ser root-owned e não graváveis pelo usuário nem grupo.
   Não há chave privada, token, PUT/GET URL nem journal gravável do
   controlador nesse diretório.
2. Acrescente `warm-publication-trust.json` com o objeto de aprovação **já
   usado pelo controlador** (`schema=tcc-warm-flight-controller-approval/v1`,
   `scope_sha256`, `observer_sha256`, `endpoint`, `publication_spki_sha256`),
   e o público `warm-publication-ed25519.pem`. As quatro chaves públicas
   devem ser distintas. O endpoint é o S3 privado fixado pelo aprovador.
3. O launcher Linux autorizado cria pipe **anônimo** e fica com sua ponta
   de escrita, vinculada ao bridge SSH autenticado/force-command.
   Lança este processo como o UID de serviço dedicado, passando somente a
   ponta de leitura com `pass_fds` no launcher (ou equivalente no
   serviço). Não redirecione stdin, use FIFO nomeado ou passe URL em argv.
   O preflight recusa FD ausente/fechado/contendo uma mensagem já enfileirada.
   O código do worker não instala SSH/host key, autorizações, ou serviço.
4. Com FD realmente fornecido pelo launcher e recibos ainda frescos:

       python -B -m infra.runpod.n20.incremental_warm_start preflight --publish-fd <FD>
       python -B -m infra.runpod.n20.incremental_warm_start run --publish-fd <FD>

   São invocações distintas; se usar preflight separado, o launcher precisa
   conservar a própria ponta de leitura e disponibilizar FD válido no
   `run`. O `run` repete as checagens antes de CUDA; não repita o registro
   da primeira lease no diário nem reutilize autorização vencida. O
   preflight não carrega pesos, não usa CUDA e não afirma que o canal
   externo entregou bytes. A sonda BF16 do runtime roda antes dos pesos.
5. Só após stdout local `sealed_for_external_put`, o bridge passa uma linha
   por caso, UTF-8 JSON com exatamente `{put_envelope,put_url}` e LF (máx.
   16 KiB), emitida pelo assinador aprovado para o ZIP e papel PUT precisos.
   A URL nunca é persistida e a entrada finaliza com falha se o canal fechar,
   o selo mudar ou a autorização for inválida/vencida. ACK é só tentativa;
   o controlador, não o Pod, usa o GET independente. Para avançar ele entrega
   o relay verificado em `warm-transition-02.json` até `-20.json`.
   O instalador privilegiado deve gravar atomicamente fora do workspace,
   dono root, grupo do serviço e modo 0440, sem sobrescrever. Passe
   recibos/relays somente no canal autenticado. A confirmação do GET final
   e do STOP exato do provedor continua externa.

Nenhum canal, chave ou host foi implantado por esta mudança. Os testes
Windows exercitam negação, framing e PUT de fixture (não rede/TLS real),
e não qualificam o próprio Linux, o SSH real ou a operação paga.
