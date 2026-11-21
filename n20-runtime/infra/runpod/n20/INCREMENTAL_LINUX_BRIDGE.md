# Ponte Linux autenticada do lote

A ponte usa os contratos do controlador existentes. Não gera credenciais,
não verifica o GET no Pod, não informa STOP, não cria Pod e não instala
OpenSSH. A permissão para rodar deve ser tratada como início de trabalho
com GPU, não como preflight.

## Provisão operacional ainda necessária

- Disponibilize o release Git limpo, root-owned, no SHA exato, o Python e
  os pesos já pinados. Use a identidade não-root dedicada do worker.
- O instalador autorizado entrega os arquivos controlados já descritos
  em INCREMENTAL_WARM_START.md, incluindo admissão/lease frescas e o pin
  da publicação. Em /etc/tcc-n20-incremental, acrescente o arquivo root-owned
  warm-linux-bridge.json com exatamente schema=tcc-warm-linux-bridge-install/v1,
  scope_sha256, service_gid, ssh_uid e ssh_gid. service_uid continua no
  trust do primeiro caso. Usuário/grupo SSH e usuário/grupo de inferência
  devem ser distintos. Os arquivos, identidades e diretórios são provisionados
  separadamente; este módulo não faz mudanças administrativas sozinho.
- Prepare /run/tcc-n20-incremental pertencente a root, sem escrita do grupo
  ou de terceiros, transitável para o grupo SSH aprovado. Não apague um
  socket existente para repetir a execução. O bridge publica só bridge.sock,
  root:grupo-SSH 0660, e confere UID+GID do outro lado via SO_PEERCRED.
- Restrinja a chave SSH do controlador a um usuário não-root e force-command
  **fixo** que chama o comando request abaixo a partir do checkout protegido.
  Sem shell interativo, PTY, AgentForwarding, port forwarding ou destinos
  livres. Fixe no controlador o ED25519 do host/exato host:port de uma
  fonte autenticada, não de ssh-keyscan sozinho. Não reutilize a conta
  SSH normal ou exponha o socket como serviço público.
- Apenas após autorização, cutoff independente longo autenticado, volume e
  trust válidos, o serviço root chama, de um cwd protegido do runtime:

      python -B -E -s -m infra.runpod.n20.incremental_linux_bridge serve

  O comando cria o pipe anônimo e lança o worker com UID/GID sem root.
  O invocador SSH restrito, para SSH_ORIGINAL_COMMAND exatamente
  tcc-official-case-bridge, deve chamar:

      python -B -E -s -m infra.runpod.n20.incremental_linux_bridge request

## Contrato

O request só passa JSON limitado às três operações fixas. fetch_archive lê
o ZIP do UUID ativo via descritores no-follow e valida as métricas/checkout
antes de devolvê-lo. send_put valida envelope/URL/selo de papel PUT,
entrega uma linha pelo pipe (limite atômico PIPE_BUF, normalmente 4096 B) e
responde QUEUED, não "R2 verificado". Em qualquer resultado ambíguo, não
repetir: o controlador reconcilia só por GET. O request nunca imprime URL.
install_relay só aceita o próximo índice/UUID exatos e as três assinaturas
já definidas do fluxo, vinculadas aos bytes selados do caso anterior; publica
root-owned 0440 por link exclusivo, relê os mesmos bytes e retorna o
digest. Reconciliação de instalação idêntica não regrava o arquivo. Nenhuma
operação aceita caminhos do cliente ou uma lease após o caso 20.

Os testes locais verificam dispatch, atomicidade lógica, scopes e falhas
com fixtures. A identidade SSH/ACL e o processo Linux real ainda devem ser
qualificados antes de Start (inclusive a ligação ao controlador externo);
não confundir a prova local com abertura do canal ou autorização paga.
