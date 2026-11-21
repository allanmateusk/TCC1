# Lote incremental RunPod: operação no mesmo Pod

## Sequência escolhida

Versionar o código e testar no GitHub, sem fazer provisionamento por Actions
na primeira rodagem. Só ligar o Pod manualmente depois da revisão dos
bloqueios abaixo. Executar a grade em ordem no mesmo Pod, mantendo carregadas
as 20 réplicas. Entre cenários, reiniciar o estado da rede e usar uma pasta
e UUID novos, sem compartilhar respostas nem reputação.

O cenário 1 é o primeiro ponto de controle. Depois de cada cenário:

1. O processo no Pod sela o ZIP no volume de rede e registra intenção de
   upload. Usa apenas uma autorização temporária de PUT para a chave exata,
   com condição de não sobrescrever.
2. O controlador independente recebe apenas a permissão de GET e confere
   bytes, SHA-256, identidade do cenário, dataset e evidência: 50 rodadas e
   1.000 gerações. Um ACK do Pod não autoriza o próximo cenário.
3. Com prova válida, libera só o próximo item, sem parar as GPUs. No último,
   para o Pod e confirma a parada no provedor.

Em falha, prazo ou transferência de resultado incerto: não avançar; reconciliar
primeiro com GET. Não repetir inferências já feitas. Se não der para confirmar,
preservar ZIP e checkpoints e emitir Stop no prazo previsto, sem Terminate.
Na recuperação, avaliar a disponibilidade de GPU separadamente do volume.
O R2 é a cópia externa; o volume é a cópia operacional, não o destino final.

## Antes de aprovar uma partida

- Confirmar versão, diff limpo e hashes do código, configuração, perguntas e
  pesos usados no Pod. A cópia local é de revisão; não é uma versão publicada.
- Confirmar disponibilidade e preço das duas H100 SXM na região do volume
  existente. Verificar montagem persistente, espaço e permissões.
- Exigir limite de tempo/custo e associação explícita ao ID do Pod para o
  mecanismo externo de parada. O mecanismo limita a cobrança se o Pod ou o
  controlador travar. O teste de CPU não comprovou parada no provedor.
- Preparar autorizações de R2 por objeto, separadas por função, em canal
  protegido. Não colocar chaves duráveis no Pod, logs, argumentos ou GitHub.
  Usar o bucket privado tcc. O backup por Windows foi verificado; o novo
  envio automático a partir do Pod ainda não.
- Integrar e qualificar a versão real antes de remover qualquer trava.
  Simulação e recibos de teste nunca são autorização de produção.
