# Primeiro cenário: 20 nós, 50 rodadas

**Estado:** revisão sem GPU. O perfil incremental ainda não está liberado para
execução, upload ou parada de Pod. O piloto de cinco rodadas é separado.

## Escopo

- ID: `e4-c0-m00-p10-exact-u00-s0`, semente 0, sem maliciosos e sem instáveis.
- SmolLM3-3B BF16, 20 réplicas, 10 por H100; 1.000 inferências próprias.
- Auditoria fixa nas rodadas 10, 20, 30, 40 e 50; nota exata.
- Apenas este cenário. Não agendar nem iniciar o segundo automaticamente.

## Antes de usar GPU

1. Revisar e empacotar a versão exata do executor como fonte reproduzível,
   com hashes de código, configuração, dataset e pesos. Não misturar o
   candidato incremental com o perfil antigo.
2. Definir teto e prazo desta primeira execução. Vincular a parada independente
   ao ID real do Pod antes de iniciar o trabalho. Confirmar Stop, não Terminate.
3. Confirmar volume persistente gravável, com espaço para os checkpoints e o
   ZIP final. Guardar o arquivo original completo, inclusive se o R2 falhar.
4. Preparar autorização temporária para o objeto exato no bucket privado
   `tcc`. O Pod precisa conseguir enviar; o controlador externo precisa
   conseguir reler. Não colocar chave mestre em código, logs ou imagem.

## Condição de sucesso

O próprio Pod fecha e envia o ZIP sem sobrescrever objeto. Um verificador
separado baixa o objeto e valida identidade, tamanho, SHA-256, 50 rodadas
e 1.000 gerações. Conflito exige releitura e comparação, nunca reenvio
destrutivo. A execução só conta como oficial com prova válida.

Falha de envio, arquivo diferente ou prazo: manter ZIP e checkpoints,
não abrir o segundo cenário e parar o Pod guardando o volume. Recuperação
de entrega não reexecuta as inferências. Confirmar o estado final no provedor.
