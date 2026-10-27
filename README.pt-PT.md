# ZeroBirus

*by Ferraz*

Ferramenta portátil para Windows 10 e 11 (x64) que guia, etapa a etapa, na deteção e remoção de mineradores de criptomoeda, trojans e outro malware. Foi pensada para correr de uma pen USB de reparação, sem instalação e sem depender de internet.

**Estado: Alpha 1.0, a primeira release oficial. As sete etapas funcionam. Foi testada num runner Windows de CI e numa corrida manual em Windows real (limpeza de temporários: quarentena, desfazer, apagar de vez). O bloqueio de firewall, a análise do Defender e a verificação pós-reinício ainda não foram experimentados em Windows real. A seguir: um modo simples de limpeza e otimização para gamers, ver `docs/ROADMAP.md`.**

## Como funciona

1. **Contexto**: o que notaste? (só muda a ordem das verificações)
2. **Verificação** (só leitura): processos, arranque, tarefas agendadas, serviços, executáveis em pastas graváveis, ligações de rede, Microsoft Defender, ficheiro hosts, assinaturas WMI.
3. **Diagnóstico**: cada achado é OK, CONFERIR, SUSPEITO ou NAO_VERIFICADO, com as razões. Uma verificação que não correu nunca é OK.
4. **Autorização**: escolhes exatamente o que pode mudar. O plano fica guardado no Ambiente de trabalho antes de acontecer seja o que for.
5. **Remoção**: ponto de restauro, informação para desfazer, e só depois os itens autorizados, cada um confirmado a reler o sistema. Remover é mover para a quarentena; tudo se pode desfazer. Opcional: mover também temporários antigos para a quarentena.
6. **Confirmação**: repetir a verificação e ver a diferença; seguir uma análise completa do Defender (o fim vem dos eventos do Defender); verificação pós-reinício.
7. **Depois**: conselhos (palavras-passe, formatar), relatório final, limpeza opcional da pasta de trabalho.

Usa a versão compilada a partir do ZIP (ver o `LEIA-ME.txt` lá dentro), ou do código: `uv sync --locked`, `uv run zerobirus gui` (janela), `uv run zerobirus scan --demo` (dados sintéticos, funciona em Linux).

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
