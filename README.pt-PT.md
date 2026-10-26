# ZeroBirus

*by Ferraz*

Ferramenta portátil para Windows 10 e 11 (x64) que guia, etapa a etapa, na deteção e remoção de mineradores de criptomoeda, trojans e outro malware. Foi pensada para correr de uma pen USB de reparação, sem instalação e sem depender de internet.

**Estado: desenvolvimento inicial (Fase 1, verificação só de leitura). Ainda não há executável nem nada para descarregar; a verificação corre a partir do código.**

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

## Verificação só de leitura (Fase 1)

`zerobirus scan` inspeciona a máquina e não altera nada: processos, arranque com o Windows, tarefas agendadas, serviços, executáveis em pastas onde o utilizador escreve, ligações a pools de mineração, Microsoft Defender, ficheiro hosts e assinaturas WMI. Cada verificação acaba em OK, CONFERIR, SUSPEITO ou NAO_VERIFICADO; uma verificação que não correu nunca conta como OK. `--json --out FICHEIRO` escreve um relatório sem segredos e sem nomes de utilizador, que podes partilhar depois de o leres. Ver `docs/DETECTION.md` e `docs/WINDOWS_TEST_PLAN.md`.

```
uv run zerobirus scan --demo            # dados sintéticos, funciona em Linux
uv run zerobirus scan --json --out relatorio.json   # só em Windows
```

Licença: MIT. Versão em inglês: [README.md](README.md).
