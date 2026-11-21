# Candidato incremental N20: Smol BF16, 20 x 50

A grade e separada do piloto antigo 20 x 5 e da campanha anterior de 17.
A revisao local nao qualifica GPU, R2 ou RunPod. Nao use flags para pular os gates.

- Fonte: 50 questoes GSM8K pinadas; mesma ordem e seed 0. Cada no consulta
  sua propria replica BF16 em cada rodada. Checkpoint retoma o mesmo cenario;
  a rodada simulada de outro cenario nunca e fonte para inferencia. Salvar o
  texto gerado e a resposta transmitida separadamente. Total planejado:
  20 cenarios x 50 rodadas x 20 nos = 20.000 geracoes.
- Grade: 7 fixos (10, 20, 30, 40 e 50), 7 sorteados (p=.2 por rodada, sem
  revelar o calendario ao ataque), 3 graduados e 3 instaveis. Os pares usam
  0, 4, 8 e 16 maliciosos; para N>0 ha controle sem conluio. Sem genese.
- Maliciosos geram normalmente nas cinco primeiras rodadas; depois, cooperam
  nas auditorias previsiveis do regime fixo. No aleatorio a decisao nao usa o
  calendario auditado. Quando atacam em conluio, aplicam o mesmo desvio de 20%
  para cima a uma resposta-base de um membro do proprio grupo (20 vira 24).
  Controles sem conluio modificam a propria resposta, sem base compartilhada.
- Instabilidade: quatro nos marcados independentemente do perfil, com 30%
  de chance de omitir cada envio, depois da geracao, inclusive em auditorias.
  A ausencia nao pode ser confundida com nao ter chamado a LLM.
- EMA: separar taxa de consenso .05 da taxa com gabarito .95 e registrar taxa
  e fonte efetivas. Medoide e notas exata (controle) ou graduada (variante).
- Acuracia principal: mesmas 50 questoes em cada cenario; relatar separadamente
  o recorte nao auditado e seu denominador. Etapas 1-3 sao leituras sem peso
  da etapa 4, e nao sao um ensaio independente sem reputacao. Uma seed nao
  estima variacao entre sementes. Fixa p=.1 versus aleatoria p=.2 compara dois
  regimes juntos; para isolar a previsibilidade, adicionar par de igual contagem.
- Antes do lote pago: provar PUT condicional mais GET autenticado e SHA no R2
  com objeto de teste autorizado, preservar volume/checkpoint em falha, medir
  dois cenarios consecutivos com replicas residentes, validar parada pelo
  provedor e teto de custo. R2 manual do piloto, se feito, nao prova o fluxo
  automatico da campanha. Os artefatos da revisao devem permanecer separados
  dos resultados oficiais.


## Verificacao sem GPU

No diretorio n20-runtime da copia de revisao, execute:
```text
python -B -m infra.runpod.n20.benchmark --campaign incremental-v1 preflight
python -B -m unittest infra.runpod.n20.test_incremental_campaign infra.runpod.n20.test_incremental_metrics infra.runpod.n20.test_campaign_profiles
```
O candidato aceita revisao offline; os modos reais e de envio continuam bloqueados.
O preflight com seed 0 gera exatamente 5 auditorias fixas e 9 sorteadas (p=.2
nao e uma cota exata). Os tres casos instaveis compartilham a mesma mascara
reproduzivel, com 60 omissoes programadas apos inferencia ao longo de 50 rodadas.
