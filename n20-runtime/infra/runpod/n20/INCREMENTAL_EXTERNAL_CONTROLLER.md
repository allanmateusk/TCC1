# Controlador externo de qualificação: primeiro → segundo caso

Continua fechado até qualificação real. Fora do Pod, num diretório privado com
ACL e SQLite durável, provisione pin do plano do observador e o SHA-256 do
`artifact_store.json_bytes` do objeto `{schema: APPROVAL, scope_sha256,
observer_sha256, endpoint, publication_spki_sha256}`. Use quatro chaves
Ed25519 distintas (observador, publicação, verificador GET, autorizador de
lease); fixe SHA-256 de DER/SPKI e proteja as chaves privadas no controlador
e no assinador autorizado correspondente. O Pod não recebe chaves,
tokens de provedor, o GET nem acesso de escrita ao diário. Não gravar URLs,
tokens ou credenciais no plano, no Git ou no Pod. O código não instala ACL.

1. `Controller.first`: observa Cloudflare e RunPod autenticados e grava a
   lease inicial no diário, antes de devolver `{observation,first_lease}`.
   A lease usa o hash canônico da evidência do observador. Entregue apenas
   via canal autenticado ao instalador protegido do Linux, usando os nomes
   de arquivo do gate warm. A saída não inicia o Pod nem um novo processo.
2. `Controller.seal_first`: obtenha o ZIP real selado por cópia autenticada
   sem modificar os bytes; o controlador valida Git, perfil, 20/50/1.000,
   ledgers, auditorias exatas e registra o lacre antes de qualquer PUT.
   O assinador de publicação emite permissões separadas vinculadas a esse
   lacre; o Pod só tem PUT condicional de criação e não repete PUT incerto.
3. `Controller.second`: faz GET independente real via adaptador assinado
   (nenhum argumento de recibo é aceito). Só permite o mesmo SHA/tamanho do
   lacre, aplica validação do ZIP, depois renova a observação exata do guard
   e assina GET e lease com papéis diferentes. `Journal.transition` grava os
   dois estados numa transação. Somente depois da confirmação retorna e
   grava `{readback,next_lease,committed}`, a atestação do commit assinada pelo
   lease. Este pacote autoriza no máximo o segundo cenário do perfil, não o
   lote inteiro, STOP ou a próxima execução. Expirou ou caiu depois do
   commit e antes da entrega? Não repita a execução. Preserve a prova e
   investigue o diário; o guard externo continua sendo a única parada.

4. `Controller.seal_second` valida o ZIP e o lease exatos do segundo
   cenário, sem tratar o sucesso do primeiro como prova do segundo. O
   assinador de publicação emite envelopes dedicados
   `tcc-incremental-second-case-publication/v1`, ligados à evidência fresca
   da segunda lease. No Pod, `publish_second_from_pod` faz o PUT condicional;
   fora dele, `Controller.finalize_second` faz GET independente, reobserva o
   guard e registra o segundo recibo no diário em transação. O terminal
   `tcc-warm-two-case-qualification-terminal/v1` comprova só os dois
   readbacks. Não autoriza cenário 3, publicação de conclusão de 20 casos
   ou STOP. O guard do prazo não foi alterado.

Fixtures locais usam HTTP falso e chaves efêmeras; os testes validam
assinaturas, bytes e transições, mas as métricas científicas da fixture
são sintéticas. Nenhuma chave, Pod ou R2 real foi usado. Ainda é necessário
verificar o Workflow hospedado, o instalador Linux e entrega no supervisor,
endpoint/permissões R2, assinador de publicação e canal autenticado de cópia.
Faça um teste R2 explícito e separado antes de Start; hardware e preço
concretos também permanecem uma decisão separada.
