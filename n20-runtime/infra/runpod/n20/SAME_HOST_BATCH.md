# Controlador offline de lote no mesmo servidor

`SameHostBatch` reaproveita a ordem oficial de 17 casos da campanha, mas tem
estado próprio, separado do controlador legado que parava o host por caso.
SQLite guarda um único servidor vinculado ao ID do lote e uma única tentativa
ativa. Cada caso ainda tem UUID próprio, ZIP e chave R2 independentes.

- Armar com uma observação autenticada do servidor exato antes de dar início ao
  trabalho. O servidor pertence ao lote, não ao UUID de um caso. O adaptador
  de nuvem, o agendador externo, a autorização de cobrança e o controle de
  acesso não fazem parte deste módulo.
- Selar hash e tamanho do ZIP antes de enviar. Só aceitar recibo de verificador
  independente que confirme os bytes para a chave, fase, caso e UUID exatos.
  Deixar o servidor ativo entre casos verificados. Nenhuma reserva pode se
  repetir após reinício ou estado incerto.
- No último recibo, erro, cancelamento, falta de heartbeat ou prazo, impedir
  casos seguintes e pedir a parada do mesmo servidor. `tick()` é dry-run por
  padrão. O adaptador de parada precisa ser idempotente, limitar chamadas
  e verificar que o provedor realmente parou o servidor. Um retorno de aceite
  não é comprovação. Nenhum volume ou dado é apagado.
- O controlador é testado com provedor falso. Não autoriza lançamento, não
  observa um serviço real e não substitui os limites do provedor. Disponibilize
  estado e relógio fora do servidor alugado, indique claramente quando não for
  possível confirmar a parada e não implante antes de testar falhas reais.
