# Parada do lote: preparo e aceite antes de ligar

A proteção não pode depender do Windows, do GitHub Actions ou do processo
de inferência. Usar agendamento durável da Cloudflare e confirmar pelo
provedor, com uma intenção de Stop persistida para o Pod exato.

## Limite

- Fixar o orçamento autorizado e a tarifa total vista no painel. O teto
  inclui a margem de atraso da parada e despesas previstas de volume; uma
  solicitação de Stop não é garantia de custo se o provedor não responder.
- Registrar um corte absoluto em UTC e um limite menor por cenário. No
  corte, não reservar novos casos e reconciliar a parada sem estender o
  prazo de um Pod já armado. A janela de 4 a 7 h é planejamento, não aprovação.
- Vincular dono, ID do Pod, região, lote, revisão e perfil. O Pod anterior e
  a inscrição do piloto não autorizam a campanha. Não reaproveitar a trava
  apagando estado; a tentativa nova deve ter escopo e registro novos.
- Fim com todos os recibos, erro definitivo e prazo convergem para a mesma
  intenção durável. Um pedido ambíguo é reconciliado por leitura do provedor;
  uma confirmação do servidor de inferência não é prova de desligamento.
  Não usar Terminate. Preservar volume e checkpoints.

## Evidência antes do uso pago

1. Testar o agendamento na Cloudflare sem credenciais RunPod (destino
   simulado). Confirmar que funciona com o Windows e o executor desconectados.
2. Preparar uma tentativa nova e verificar, fora do Pod, que o agendamento
   está ativo e com identidade/prazo corretos antes de iniciar inferência.
3. Provar que o primeiro cenário não para o Pod quando seu ZIP é validado;
   só o terminal global ou prazo autoriza Stop.
4. No teste do provedor, observar o Pod exato até que conste parado. Se o
   estado continuar incerto, avisar e usar a parada manual, sem apagar nada.

Não usar o antigo flag do runpodctl como proteção. A documentação oficial
da RunPod relata que as versões antigas aceitavam esse flag, mas o backend
não o aplicava:
https://github.com/runpod/runpod-plugins-official/blob/main/plugins/runpod/skills/runpod-usage/reference/getting-started.md
A capacidade de aguardar horas existe no Workflows, mas precisa ser usada por
uma versão nova do guardião; não altera o limite do piloto já implantado:
https://developers.cloudflare.com/workflows/reference/limits/
