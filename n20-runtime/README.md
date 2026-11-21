# TCC N20: runtime isolado

Esta pasta contém a configuração do experimento SmolLM3-3B em 20 nós e
50 rodadas, isolada do simulador e do texto históricos da branch principal.
Use o [guia do experimento](infra/runpod/n20/README.md).

O runtime foi extraído do commit de trabalho `14feea7879051beb9da84a97fe0a642c37569d14`
sem importar seu histórico. O subconjunto GSM8K preserva ordem, IDs, perguntas e
gabaritos, sem incluir gerações anteriores nem resultados.
