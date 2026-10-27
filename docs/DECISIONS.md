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

## D-006 Temporários passam pela quarentena

O pedido de "apagar temporários" cumpre-se sem quebrar a regra de nunca apagar: entradas de topo de `%TEMP%` do utilizador (mais de 2 dias, máx. 200, links nunca) são oferecidas desmarcadas e movidas para a quarentena; só "Apagar a quarentena de vez" apaga, com confirmação. Se estiver errado: custa espaço em disco na quarentena até se apagar.

## D-007 Restauro de ponto: parar e perguntar

Se o ponto de restauro não puder ser criado, a remoção pára e pede confirmação explícita para continuar (BRIEF §5). O ZeroBirus não liga a Proteção do Sistema por si.

## D-008 Fim da análise do Defender

Decidido por eventos 1000/1001/1002/1005 desde o início e pelo processo que lançámos; processo desaparecido sem evento de fim é "não foi possível saber", nunca "concluída". O 1005 só está confirmado por uma resposta da comunidade Microsoft; 1000 a 1002 pela documentação.

## D-009 Reativar proteções desligadas não faz parte da v1

O ZeroBirus nunca liga nem desliga antivírus ou proteções. Fica para depois, com a mesma exigência de plano autorizado.

## D-010 Release em rascunho

O workflow de release cria sempre um rascunho; publicar é manual. Ensaio: `workflow_dispatch`.

## D-011 Primeira release: Alpha 1.0

A pedido do João, depois do primeiro teste em Windows real, a versão atual é publicada como pré-release "ZeroBirus Alpha" com a tag v1.0.0. É um alpha: o que não foi provado em Windows real está dito no README e no STATUS. Se estiver errado: a release despublica-se ou apaga-se.

## D-012 Firewall: verificação por números

O `Get-NetFirewallRule` devolve `Action` e `Direction` como números (4 e 2) no runner; a verificação comparava com texto e nunca confirmava, apesar de a regra ser criada. Passou a comparar números. Encontrado pelo teste de integração e pelo diagnóstico no log do CI.
