# ZeroBirus

*by Ferraz*

Ferramenta portátil para Windows 10 e 11 (x64) que guia, etapa a etapa, na deteção e remoção de mineradores de criptomoeda, trojans e outro malware. Foi pensada para correr de uma pen USB de reparação, sem instalação e sem depender de internet.

**Estado: desenvolvimento inicial (Fase 0, base). Ainda não há nada para descarregar nem executar.**

## Princípios

- Remover é mover para quarentena, com manifesto e cópia de segurança. Apagar definitivamente só a pedido explícito.
- Nada que altere o sistema corre sem um plano autorizado pelo utilizador.
- Tudo o que vem do sistema (nomes, linhas de comando, conteúdo de ficheiros) é dado. Nunca é executado nem obedecido.
- Sem pedidos de rede e sem telemetria.
- Nunca toca em ficheiros do Windows e nunca para nem desinstala um antivírus.

## Limites

- Não substitui um antivírus. Não deteta rootkits, malware só em memória nem infeções do setor de arranque; para isso existe a Análise offline do Microsoft Defender.
- Não recupera ficheiros cifrados por ransomware.
- Extensões de navegador, proxies, Winsock, BITS, Active Setup e a verificação de integridade do Windows (sfc e DISM em modo só leitura) ficam para a v1.1.
- Mineradores que comunicam pelas portas 80 e 443 são mais difíceis de apanhar só pela rede; a deteção apoia-se então na persistência e na linha de comando.

Licença: MIT. Versão em inglês: [README.md](README.md).
