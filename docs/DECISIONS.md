# DECISIONS

Decisões técnicas tomadas durante o desenvolvimento autónomo que não estão no BRIEF. Regra seguida em todas: o lado mais seguro. Cada uma tem a razão e o que muda se estiver errada.

## D-001 Política única de URLs no redact

Utilizador ou carteira numa URL `stratum+tcp`, `stratum+ssl`, `stratum+tls`, `stratum+udp`, `stratum2+tcp` ficam visíveis e vão para a lista de indicadores do relatório; palavras-passe sempre ocultas; utilizador e palavra-passe de qualquer outro esquema ocultos. Razão: o utilizador de uma URL de pool é dado do atacante e é o que se usa para investigar; noutros URLs pode ser da vítima. O utilizador só fica visível se for texto simples (`[A-Za-z0-9._-]`, até 256). Uma carteira fora de uma URL stratum (por exemplo `-u CARTEIRA`) continua oculta, porque aí não há garantia de que é do atacante.

## D-002 Indicadores sem fonte pesam menos

Indicador de mineração sem fonte pública: "não verificado", só sinais fracos, nunca SUSPEITO sozinho, nunca corrobora a exclusão de uma unidade do Defender. Razão: o BRIEF manda não adivinhar. Consequência assumida: quase todas as portas de pools (4444, 5555, 7777, 14444...) ficaram não verificadas porque nenhuma página oficial legível as lista; só a 3333 está verificada. Se um pool publicar as portas, passa a verificado editando `miners.json`.

## D-003 Perfis sem sessão

Uma só linha agrupada, NAO_VERIFICADO, sem alarme; nunca se monta um hive (`reg load`). Issue #5 para ler hives offline em v1.1.

## D-004 PowerShell: `-EncodedCommand` mantido

Ambiente do filho construído de raiz com lista permitida; `system_root` de `GetSystemWindowsDirectoryW` (também na expansão de valores do registo); saída limitada a 32 MB (o filho é morto); stderr cortado e redigido; assinaturas em lotes de 200; cada script devolve itens mais erros por item. Razão para manter `-EncodedCommand`: não deixa scripts no disco que alguém possa substituir entre escrita e execução. Se o teste manual mostrar reação de Defender, SmartScreen ou EDR, passa a `-File` com verificação do hash (ver WINDOWS_TEST_PLAN).

## D-005 Barra lateral sem scrollbars

A barra de etapas tem sempre 7 linhas curtas; scrollbars só ocupavam a largura da versão compacta (a 150%, 853x480 lógicos) e cortavam a última etapa. Ficam desligadas e as linhas têm menos padding. Se uma etapa nova fizer a lista não caber em 460 pontos de altura, é preciso rever o layout, não voltar às scrollbars.
