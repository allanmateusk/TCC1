# Preflight BF16 no host do experimento

No mesmo container, usuário e Python que executarão a campanha, antes de
carregar pesos, o preflight registra somente versão do driver NVIDIA,
versão do PyTorch e build CUDA, arquiteturas compiladas, nome e capacidade
de computação por GPU. Em cada GPU testa BF16 nativo, aloca uma matriz
2x2 na própria GPU, executa soma e multiplicação matricial, sincroniza
explicitamente e compara valores, dispositivo e dtype. Uma resposta
positiva de is_bf16_supported isolada não é prova suficiente.

Após autorização do host e somente antes de inferência, a sonda também
pode rodar sozinha, sem pesos, com timeout do Linux:

    timeout 40s python -B -m infra.runpod.n20.cuda_bf16_probe --devices 2

A execução comum e a warm já chamam essa sonda em benchmark.verify_cuda_hardware,
antes de ativar residentes. Em caso de falha, não instalar/alterar
dependências nem mudar para FP16/NF4 no meio do lote; inspecionar a combinação
exata de driver/wheel e usar o STOP supervisionado se o host for pago.
O teste de kernel não prova capacidade para 20 modelos; mantêm-se medições
de VRAM e a margem do perfil.

A NVIDIA lista [RTX PRO 6000 Blackwell como CC 12.0](https://developer.nvidia.com/cuda/gpus).
O [PyTorch 2.7](https://pytorch.org/blog/pytorch-2-7/) iniciou suporte Blackwell
em builds CUDA 12.8. O [PyTorch 2.12](https://pytorch.org/blog/pytorch-2-12-release-blog/)
orienta CUDA 13.0+ para Blackwell em sua matriz mais nova, com driver compatível.
Não inferir compatibilidade real pelo anúncio do Pod.
