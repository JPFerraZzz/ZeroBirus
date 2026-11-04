# Feedback do João às capturas da Fase 6 (texto original, 2026-10-28)

Guardado tal como foi escrito, para a revisão completa. O que foi feito com ele está em `docs/ROADMAP.md`. Em caso de dúvida, vale este texto.

## Texto original

Meu feedback das prints da fase 6:

- Gostei do que vi nas prints mas quero que organizes melhor a área de diagnóstico:
    - Organiza os incidentes numa tabela de risco nestes níveis de forma adequada: 1º Incomum; 2º Anómalo ; 3º Suspeito; 4º Grave; 5º Crítico
    - Decide os que devem ser tomados por cada nível
    - Descarta arquivos temporários e lixo apenas na limpeza profunda, estes devem ter um campo Slidebox "Arquivos Temporários"
    - Arranja um novo método de sinalizar os incidentes a apagar, sugerindo apagar como predefinido os Críticos e Graves (mas com opção de desmarcar por própria conta e risco)

Menus a fazer:

- Modo Jogo que tenha estas opções:
    - FPS Optimizer: Tudo o que rende para o ganho de FPS quero que seja atribuido aqui.
    - RAM Lover: Faz um diagnóstico simples sobre a vida da RAM e otimiza-a ao máximo.
    - MegaTweaker:
        - Desliga settings que todos desativam quando querem ter um PC full gamer, estilo https://github.com/christitustech/winutil (acho possível, organiza da mesma forma)

- Uma área de tweak geral (nao sei como se dizer, mas quero que faça isto, depois dás um nome)
    - FirstSetup: Estilo https://ninite.com/; Mas com os gerais (Web Browsers, Messaging, Other, Media, Utilities, Compression, Developer Tools), quero exatamente iguail ao Ninite e que dê no fim um executável na área de trabalho com a minha marca de água e isso que instale isso tudo
    - AllUp: Permite atualizar todos os serviços e apps windows (estilo winget)
    - BigDiag: Mega relatório de diagnóstico de tudo do pc (Resultados MRT, RAM, SSD, etc...)
    - AllDrivers: Permite atualizar todos os drivers do PC que tenha atualização nova existente.

- Nerd'O: O painel de limpeza avançada (o layout existente todo sem ter os Modos)

Pronto tens Nomes de dois menos da área de "tweak" geral, dá um nome fixe apropriado.
Com isso, com isso tem em conta que deves criar uma app principal com essas 3 opções e que cada uma dessas abra uma nova janela a qual selecionado (1 menu geral principal, 3 menus embutidos, dentro do Modo Jogo ter um menu para o MegaTweaker próprio pq tem mais configs, dento da área de tweak geral um menu para o FirstSetup (estilo ninite) e outro para o BigDiag, e um menu que praticamente ja existe que é o do Nerd'O).

Faz primeiro o necessário pendente simples e organizas o que temos para tentares encaixar isto para podermos fazer tudo mas de forma correta (não quero engonhar e demorar bue por isso tem de ser objetivo).

## Checklist para a revisão

Cada pedido, e onde está tratado. Marcar na revisão.

| Pedido | Onde | Estado |
| --- | --- | --- |
| Tabela de risco com 5 níveis (Incomum, Anómalo, Suspeito, Grave, Crítico) | ROADMAP, "Diagnóstico do Nerd'O" | planeado, Fase 7 |
| Decidir a ação por nível | ROADMAP, tabela de risco | proposto, falta o João confirmar |
| Temporários e lixo só na limpeza profunda, num campo recolhível "Arquivos Temporários" | ROADMAP, "Arquivos Temporários" | planeado, Fase 7 |
| Novo método de sinalizar, Críticos e Graves marcados por omissão, desmarcáveis por conta e risco | ROADMAP, "Sinalização" | planeado, Fase 7 |
| Modo Jogo: FPS Optimizer | ROADMAP, "Modo Jogo" | planeado, Fase 8 |
| Modo Jogo: RAM Lover | ROADMAP, "Modo Jogo" | planeado, Fase 8 |
| Modo Jogo: MegaTweaker (estilo winutil, menu próprio) | ROADMAP, "Modo Jogo" | planeado, Fase 9; decisão 3 |
| Área de tweak geral com nome | ROADMAP: "PitStop" (proposta minha) | falta o João confirmar o nome |
| FirstSetup estilo Ninite, mesmas categorias, executável no ambiente de trabalho com a marca | ROADMAP, "PitStop" | Fase 11; decisão 1 (rede) |
| AllUp (estilo winget) | ROADMAP, "PitStop" | planeado, Fase 10 |
| BigDiag (MRT, RAM, SSD, etc.) | ROADMAP, "PitStop" | planeado, Fase 10 |
| AllDrivers | ROADMAP, "PitStop" | Fase 11; decisão 2 |
| Nerd'O = layout atual sem os Modos | ROADMAP, "Estrutura" | planeado, Fase 7 |
| App principal com 3 opções, cada uma abre janela própria; submenus para MegaTweaker, FirstSetup e BigDiag | ROADMAP, "Estrutura" | planeado, Fase 7 (esqueleto) |
| Ser objetivo, sem demorar | Fases curtas, uma de cada vez | em curso |
