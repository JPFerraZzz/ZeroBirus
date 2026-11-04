# DESIGN

Direção visual e de interação da interface do ZeroBirus. Escrito antes de qualquer código de interface (BRIEF §11). Cada escolha está justificada pelo contexto, não pelo gosto. O tema vive num único ficheiro, `src/zerobirus/ui/theme.py`, e os valores da tabela de tokens abaixo são gerados dele (`tools/update_design_doc.py`) e testados.

## 1. Contexto de que tudo deriva

Quem usa: alguém sentado à frente de um PC avariado, muitas vezes sob stress, às vezes um portátil modesto, ecrã mau, escalonamento alto, num sítio com luz forte (oficina, sala). Pode ser o João ou uma pessoa sem conhecimento técnico a seguir instruções. A pessoa vai autorizar remoções: o que cada botão faz tem de ser óbvio. O ecrã principal é a tabela de diagnóstico (Item, Onde está, Nível, O que é) e o resto organiza-se à volta dela.

Daqui saem quatro exigências que decidem o resto:

1. **Legibilidade em condições más.** Contraste alto, texto grande o bastante, nada que dependa de pormenor fino ou de cor para ser entendido.
2. **Calma.** Sem alarme decorativo. Uma ferramenta que mexe no sistema tem de parecer sóbria e previsível, não urgente.
3. **Decisões sem ambiguidade.** Ações destrutivas têm fricção proporcional; a ação segura é sempre a mais fácil de alcançar e a que recebe o foco por omissão.
4. **Funcionar pequeno.** 1280x720 a 150% de escalonamento são cerca de 853x480 pontos lógicos. É o caso de projeto, não o caso extremo: tudo tem de ser usável ali, com teclado.

## 2. Carácter

Revisto na Fase 6 (ver `docs/ROADMAP.md`). A primeira versão era "um formulário bem impresso": papel quente, sem cartões. Depois do primeiro teste em Windows real, o produto ganhou um modo simples para gamers e uso diário, e o carácter passou a ser **um painel escuro e sóbrio**: fundo quase preto frio, uma única cor de acento menta-ciano, números grandes em tipo monoespaçado, cartões de cantos suaves. "Gamer sem exagero" quer dizer: nenhum néon a brilhar, nenhum gradiente, nenhuma sombra, nenhuma animação decorativa. A seriedade vem de que a mesma interface autoriza remoções: a fricção e a clareza da secção 3.8 mantêm-se tal e qual.

A estrutura continua a ser título, uma frase que diz o que vai acontecer, o conteúdo e uma barra de ações em baixo. O ecrã inicial é a exceção: um menu de cartões (secção 3.11).

## 3. Decisões

### 3.1 Cor

Um tema escuro único. Razões: (a) é o que quem joga espera e usa; (b) um segundo tema duplica a superfície a testar e a rever; (c) o preto puro e o branco puro cansam, por isso o fundo é um quase-preto frio (`paper`) e o texto um branco-azulado (`ink`), nunca `#000` nem `#FFF`. A decisão anterior (tema claro, por causa de ecrãs maus e luz forte de oficina) foi revogada: o contraste continua a ser verificado por teste (AA, 4.5:1) e o modo de contraste elevado do Windows continua a usar a paleta do sistema (ver 3.7).

Uma só cor de ação, menta-ciano (`accent`), usada para o botão principal, o anel de foco, os números grandes e o contorno do cartão da análise profunda. O texto sobre ela é quase-preto (`on_accent`). Tudo o resto é tinta, cinza frio e as quatro cores de nível, claras e dessaturadas sobre fundos escuros suaves. Nunca há gradientes, brilho, azul e roxo a competir, nem sombras.

**O estado nunca depende só da cor.** Cada nível tem uma forma e um texto: SUSPEITO é um losango cheio com a palavra, CONFERIR um triângulo, OK um círculo, NAO_VERIFICADO um quadrado tracejado. Um teste confirma que as quatro formas são distintas e que o texto está sempre presente.

### 3.2 Tipografia

A fonte do sistema: Segoe UI no Windows (Segoe UI Variable quando existir), e uma sans do sistema noutros. Razões: não há ficheiros de fonte para distribuir nem licenças, é a fonte que o Windows já otimizou para o ClearType e para os acentos do português, e é a mesma dos diálogos do sistema que a pessoa já conhece. Detalhe técnico (caminhos, linhas de comando, hashes) em Cascadia Mono, com Consolas como alternativa: largura fixa para comparar caracteres.

Escala curta e sem corpo pequeno: corpo 10 pt, secundário 9 pt (nunca menos), cabeçalho de página 16 pt semibold, subtítulo 12 pt semibold. Texto longo em colunas de 60 a 80 carateres no máximo. Alinhado à esquerda, sem justificar.

### 3.3 Espaçamento e ritmo

Grelha de 4. Dentro de uma linha ou de um grupo o espaço é curto (4 a 8); entre grupos é largo (24 a 32); a margem da página é maior (32). A diferença de escala entre "dentro" e "entre" é o que cria hierarquia, em vez de espaçamento uniforme. Linhas da tabela com altura mínima de 36 px: alvo confortável para rato e legível a 150%.

### 3.4 Forma

Botões, campos e tabelas: quase quadrados (raio de 2 px, bordas de 1 px). **Cartões e grupos** (menu inicial, grupos da Autorização): raio de 8 px (`radius_card`), borda de 1 px, fundo `card` um degrau acima do `paper`. Sem sombras e sem elevação: a hierarquia faz-se por tom de fundo, linhas finas e espaço.

### 3.5 Estrutura das páginas

- **Barra lateral de etapas** à esquerda, sempre visível: Contexto, Verificação, Diagnóstico, Autorização, Remoção, Confirmação, Depois. Mostra o número, o nome e o estado (concluída, atual, por fazer). Só a etapa atual e as concluídas são acessíveis: não se avança sem o utilizador carregar (BRIEF §4). Abaixo de cerca de 1000 pontos de largura passa a mostrar só os números, com o nome da etapa atual no cabeçalho. Por cima da lista, a ligação "Menu inicial" leva ao ecrã inicial (desativada enquanto a verificação ou a remoção correm).
- **Cabeçalho da página:** título e, por baixo, uma frase em linguagem simples que diz o que a etapa vai fazer (BRIEF §5, etapa 1).
- **Conteúdo.** Na etapa de diagnóstico: a tabela em cima, o painel de detalhe por baixo (não ao lado, porque a largura é o recurso mais escasso), separados por um divisor que se arrasta.
- **Barra de ações em baixo,** com o botão principal à direita e a ação segura à esquerda.

### 3.6 Duas camadas de leitura

Por omissão, linguagem simples: "O que é" numa frase, "Por que é suspeito" em lista de sinais com o texto em português. Um botão "Mostrar detalhe técnico" (e a tecla T) acrescenta, em letra de largura fixa, o caminho, a linha de comando já sem segredos, o SHA-256 e os códigos dos sinais. Tudo o que vem do sistema é mostrado como texto simples (`Qt.PlainText`), nunca como HTML; um teste percorre todos os rótulos e células.

### 3.7 Movimento

Quase nenhum. A única coisa que se move é a barra de progresso da verificação, e é determinada (X de 9 verificações) com texto, porque quem espera precisa de saber quanto falta. Não há transições entre páginas, nem animações de entrada. Se o Windows tiver a animação desativada (reduzir animações), não há sequer o indicador de ocupado animado: aparece só o texto. O modo de contraste elevado do Windows desliga o nosso estilo e usa a paleta do sistema.

### 3.8 Fricção e a ação segura

Na autorização e na remoção:

- O botão que remove diz exatamente o que faz e quantos itens ("Remover os 3 itens da lista") e usa a cor de perigo; nunca se chama só "OK" ou "Continuar".
- O foco inicial, Enter e Esc vão sempre para a ação segura ("Voltar", "Manter tudo", "Cancelar").
- O botão de remover só fica ativo depois de a pessoa marcar "Li a lista e percebo que estes itens vão para a quarentena". Se o plano é grande (mais de 20 itens, ou pastas), pede-se uma segunda confirmação dita pelo número de itens.
- Os itens CONFERIR nunca vêm marcados e são decididos um a um (Remover, Manter), com "Manter" como valor por omissão.
- O texto diz sempre que remover é mover para a quarentena e que se pode desfazer.

### 3.9 Teclado e acessibilidade

Ordem de tabulação igual à ordem visual. Todos os botões têm atalho Alt com a letra sublinhada em português. Anel de foco visível de 2 px na cor de ação, em todos os elementos que aceitam foco. A tabela navega por setas, Início, Fim e Enter abre o detalhe. Os nomes acessíveis (`accessibleName`) estão definidos nos elementos que não têm texto. Texto secundário nunca abaixo de 9 pt e todos os pares de cor de texto passam o contraste AA (4.5:1), verificado por teste.

### 3.10 Identidade

O nome é ZeroBirus, com a assinatura "by Ferraz" mais pequena e em tinta secundária. O sinal é original: um anel grosso, quase um zero, com um pequeno quadrado encaixado numa abertura do traço. Lê-se como "zero" e como "o que ficou de fora do anel". Não é um escudo, não tem visto, não imita marcas de antivírus. Está em `src/zerobirus/ui/assets/logo.svg`, e o ícone `packaging/zerobirus.ico` é gerado dele (`tools/make_icon.py`) em 16, 24, 32, 48, 64, 128 e 256 px.

### 3.11 Ecrã inicial e janelas

Revisto na Fase 7 (ver `docs/ROADMAP.md`, D-014). O ecrã inicial é o **menu principal** e tem exatamente três cartões, em fila a largura normal e empilhados quando é estreito: **Modo Jogo**, **PitStop** e **Nerd'O**. Cada cartão tem título, uma frase e, quando o módulo ainda não existe, a marca "Em breve". O Nerd'O (a análise profunda) mantém o contorno em `accent` e o texto maior: é o que distingue o ZeroBirus.

Cada cartão abre **a sua janela**, com o mesmo tema e a mesma barra lateral:

- **Modo Jogo** e **PitStop** abrem uma janela com os módulos em cartões (FPS Optimizer, RAM Lover, MegaTweaker; FirstSetup, AllUp, BigDiag, AllDrivers). MegaTweaker, FirstSetup e BigDiag terão submenu próprio quando forem construídos. Na Fase 7 são esqueleto: cada módulo mostra "Em breve" e o que vai fazer.
- **Nerd'O** abre o fluxo de sete etapas já existente, sem modos.

Cada janela tem "← Menu principal" no topo da barra lateral (desativado enquanto algo corre). Cada cartão é um único botão (foco por teclado, Enter ou Espaço abrem, anel de foco em `accent`, nome acessível = título + frase). Um módulo "Em breve" não faz nada além de mostrar essa nota.

### 3.12 Níveis de risco e grupos (Nerd'O)

Cinco níveis, do mais leve ao mais grave: **Incomum, Anómalo, Suspeito, Grave, Crítico** (BRIEF §9 e D-015). Cada incidente tem um **selo de nível**: uma forma, a palavra e a cor, nunca só a cor. As formas são todas distintas (anel, alvo, triângulo, losango cheio, losango duplo) e um teste confirma-o. As cores reutilizam as existentes, sem acrescentar nenhuma: cinza frio (Incomum), âmbar (Anómalo e Suspeito) e coral (Grave e Crítico). Quem distingue os pares de mesma cor é a forma e a palavra.

Na Autorização a lista fica **agrupada por nível**, do Crítico para o Incomum. Cada grupo é recolhível (cabeçalho com seta, título, contagem e quantos estão marcados). **Grave e Crítico vêm marcados por omissão**; os restantes, desmarcados. Desmarcar é sempre possível, com o texto curto "por tua conta e risco" por baixo do grupo marcado. Marcado nunca significa executado: o plano continua a precisar de autorização e o botão de remover mantém a fricção da 3.8. Abrem por omissão os grupos Crítico e Grave; os outros ficam fechados.

**Arquivos Temporários** é um grupo à parte, recolhível, fora da tabela de risco, sempre desmarcado, no fim da lista. Só existe no Nerd'O.

### 3.13 Módulos do Modo Jogo

FPS Optimizer e RAM Lover são ecrãs da mesma janela, abertos a partir do cartão do módulo, com "← Modo Jogo" à esquerda e a ação principal à direita. Cada escolha é uma caixa com o nome, uma frase simples e, por baixo, o estado ("Já está assim", "Não existe neste PC", "Precisa de administrador"). As definições seguras vêm marcadas, as moderadas não; no RAM Lover nenhum programa vem marcado e fechar exige uma caixa de confirmação. O botão diz o que faz e quantos itens ("Aplicar 3 definições", "Fechar 2 programas"). Depois de aplicar, cada item mostra o resultado confirmado e "Repor tudo" volta ao valor anterior; fechar programas não tem "Repor" e o texto diz porquê.

## 4. Padrões a evitar (verificação)

Lista do BRIEF §11 e como a interface a cumpre:

| Padrão a evitar | Como foi evitado |
| --- | --- |
| Gradientes decorativos, neon azul e roxo, glassmorphism, sombras difusas | Cores planas, uma só cor de ação (menta-ciano, sem brilho), nenhuma sombra nem transparência. |
| Grelha de cartões iguais com ícone em círculo colorido | Só o menu principal usa cartões (três), sem ícones em círculos, e o do Nerd'O é diferente dos outros (contorno em accent). As páginas de trabalho mantêm a estrutura título, frase, conteúdo, barra de ações. |
| Emojis como ícones | Nenhum emoji. Os níveis usam formas desenhadas mais texto. |
| Terminal de filme (verde sobre preto) | Tema escuro frio com um único acento menta-ciano; sem verde fosforescente, sem efeito de terminal. A letra de largura fixa só aparece no detalhe técnico e nos números grandes. |
| Escudo com visto e texto de marketing | Sinal geométrico original. Textos factuais, sem promessas ("Protege o teu PC" não existe). |
| Cantos muito redondos, espaçamento uniforme sem hierarquia | Raio de 2 px nos controlos e de 8 px só nos cartões. Dois ritmos de espaçamento (dentro e entre) e escala tipográfica com títulos e corpo bem distintos. |
| Animações sem função | Só a barra de progresso. Nada mais se move. Respeita a definição de reduzir animações. |

As capturas de ecrã a 100% e a 150%, geradas pelo CI Windows e guardadas como artefactos (`zerobirus-screenshots`), servem para rever isto sobre a interface real.

## 5. Tokens

<!-- generated:tokens:start -->
| Token | Valor |
| --- | --- |
| `paper` | `#0E1218` |
| `surface` | `#151B24` |
| `card` | `#182030` |
| `card_hover` | `#1F2A3D` |
| `ink` | `#E8ECF1` |
| `ink_muted` | `#9DA7B5` |
| `rule` | `#6B7788` |
| `rule_soft` | `#273040` |
| `selection` | `#1D2B3A` |
| `accent` | `#2BD9B4` |
| `accent_hover` | `#55E6C6` |
| `on_accent` | `#04211B` |
| `suspeito` | `#FF8F86` |
| `suspeito_bg` | `#3A1C20` |
| `conferir` | `#F0C050` |
| `conferir_bg` | `#34290F` |
| `ok` | `#62D890` |
| `ok_bg` | `#14301F` |
| `nao_verificado` | `#A9B2BF` |
| `nao_verificado_bg` | `#232A34` |
| `danger` | `#C23B3B` |
| `on_danger` | `#FFFFFF` |
| `disabled` | `#8591A3` |
| `font_body_pt` | `10.0` |
| `font_small_pt` | `9.0` |
| `font_title_pt` | `16.0` |
| `font_subtitle_pt` | `12.0` |
| `font_metric_pt` | `22.0` |
| `font_family` | `"Segoe UI Variable Text", "Segoe UI", "Noto Sans", "DejaVu Sans", sans-serif` |
| `font_mono` | `"Cascadia Mono", Consolas, "DejaVu Sans Mono", monospace` |
| `space_1` | `4` |
| `space_2` | `8` |
| `space_3` | `12` |
| `space_4` | `16` |
| `space_5` | `24` |
| `space_6` | `32` |
| `row_height` | `36` |
| `radius` | `2` |
| `radius_card` | `8` |
| `focus_width` | `2` |

Contrastes (WCAG, mínimo 4.5:1 para texto e 3:1 para elementos sem texto):

| Par | Rácio | Onde |
| --- | --- | --- |
| `ink` sobre `paper` | 15.83 | body text on the page |
| `ink` sobre `surface` | 14.58 | table and text areas |
| `ink_muted` sobre `paper` | 7.72 | secondary text on the page |
| `ink_muted` sobre `surface` | 7.11 | secondary text in tables |
| `ink` sobre `card` | 13.74 | text on a card |
| `ink_muted` sobre `card` | 6.70 | secondary text on a card |
| `accent` sobre `card` | 9.07 | accent text on a card |
| `ink` sobre `card_hover` | 12.15 | text on a hovered card |
| `ink_muted` sobre `card_hover` | 5.92 | secondary text on a hovered card |
| `ink` sobre `selection` | 12.13 | selected row |
| `on_accent` sobre `accent` | 9.44 | primary button |
| `on_accent` sobre `accent_hover` | 10.92 | primary button hovered |
| `accent` sobre `paper` | 10.45 | links and accent text |
| `on_danger` sobre `danger` | 5.27 | destructive button |
| `suspeito` sobre `paper` | 8.52 | level text |
| `suspeito` sobre `suspeito_bg` | 6.97 | level text on its tint |
| `conferir` sobre `paper` | 11.05 | level text |
| `conferir` sobre `conferir_bg` | 8.41 | level text on its tint |
| `ok` sobre `paper` | 10.50 | level text |
| `ok` sobre `ok_bg` | 7.98 | level text on its tint |
| `nao_verificado` sobre `paper` | 8.77 | level text |
| `nao_verificado` sobre `nao_verificado_bg` | 6.75 | level text on its tint |
| `disabled` sobre `paper` | 5.88 | disabled text |
| `rule` sobre `paper` | 4.13 | borders of inputs and tables |
| `accent` sobre `paper` | 10.45 | focus ring |
| `rule` sobre `card` | 3.59 | borders of cards |
<!-- generated:tokens:end -->
