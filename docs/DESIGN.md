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

Um formulário bem impresso, não um painel de controlo. A referência é o relatório de um técnico ou um manual de oficina: papel quente, tinta escura, linhas finas para separar, hierarquia feita de peso e de espaço e não de caixas coloridas. Por isso não há cartões, sombras nem ícones decorativos: a estrutura é título, uma frase que diz o que vai acontecer, o conteúdo, e uma barra de ações em baixo.

## 3. Decisões

### 3.1 Cor

Um tema claro, quente e de contraste alto, único. Razões: (a) em ecrãs maus e com luz ambiente, texto escuro sobre fundo claro aguenta-se melhor do que o inverso; (b) um segundo tema duplica a superfície a testar e a rever sem resolver nenhum problema do contexto; (c) o branco puro cansa e encadeia em ecrãs sem calibração, por isso o papel é um branco quente. Se o Windows estiver em modo de contraste elevado, a interface não impõe cores: usa a paleta do sistema (ver 3.7).

Uma só cor de ação (um azul-petróleo escuro), usada só para o botão principal e para o foco. Tudo o resto é tinta, cinza quente e as quatro cores de nível. As cores de nível são escuras e dessaturadas de propósito: têm de passar AA como texto sobre o papel e sobre o seu próprio fundo suave, e não podem parecer sinal de trânsito. Nunca há gradientes, nem neon, nem azul e roxo.

**O estado nunca depende só da cor.** Cada nível tem uma forma e um texto: SUSPEITO é um losango cheio com a palavra, CONFERIR um triângulo, OK um círculo, NAO_VERIFICADO um quadrado tracejado. Um teste confirma que as quatro formas são distintas e que o texto está sempre presente.

### 3.2 Tipografia

A fonte do sistema: Segoe UI no Windows (Segoe UI Variable quando existir), e uma sans do sistema noutros. Razões: não há ficheiros de fonte para distribuir nem licenças, é a fonte que o Windows já otimizou para o ClearType e para os acentos do português, e é a mesma dos diálogos do sistema que a pessoa já conhece. Detalhe técnico (caminhos, linhas de comando, hashes) em Cascadia Mono, com Consolas como alternativa: largura fixa para comparar caracteres.

Escala curta e sem corpo pequeno: corpo 10 pt, secundário 9 pt (nunca menos), cabeçalho de página 16 pt semibold, subtítulo 12 pt semibold. Texto longo em colunas de 60 a 80 carateres no máximo. Alinhado à esquerda, sem justificar.

### 3.3 Espaçamento e ritmo

Grelha de 4. Dentro de uma linha ou de um grupo o espaço é curto (4 a 8); entre grupos é largo (24 a 32); a margem da página é maior (32). A diferença de escala entre "dentro" e "entre" é o que cria hierarquia, em vez de espaçamento uniforme. Linhas da tabela com altura mínima de 36 px: alvo confortável para rato e legível a 150%.

### 3.4 Forma

Quase quadrada: raio de 2 px, bordas de 1 px, sem sombras. Elevação nenhuma. A separação é feita por linhas finas e por espaço. Razão: cantos muito redondos e sombras difusas são o sinal visual de interface de marketing, e não dizem nada a quem está a decidir se autoriza uma remoção.

### 3.5 Estrutura das páginas

- **Barra lateral de etapas** à esquerda, sempre visível: Contexto, Verificação, Diagnóstico, Autorização, Remoção, Confirmação, Depois. Mostra o número, o nome e o estado (concluída, atual, por fazer). Só a etapa atual e as concluídas são acessíveis: não se avança sem o utilizador carregar (BRIEF §4). Abaixo de cerca de 1000 pontos de largura passa a mostrar só os números, com o nome da etapa atual no cabeçalho.
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

## 4. Padrões a evitar (verificação)

Lista do BRIEF §11 e como a interface a cumpre:

| Padrão a evitar | Como foi evitado |
| --- | --- |
| Gradientes decorativos, neon azul e roxo, glassmorphism, sombras difusas | Cores planas, uma só cor de ação em azul-petróleo escuro, nenhuma sombra nem transparência. |
| Grelha de cartões iguais com ícone em círculo colorido | Sem cartões. Estrutura de formulário: título, frase, conteúdo, barra de ações. Sem ícones decorativos. |
| Emojis como ícones | Nenhum emoji. Os níveis usam formas desenhadas mais texto. |
| Terminal de filme (verde sobre preto) | Tema claro, papel quente e tinta escura. A letra de largura fixa só aparece no detalhe técnico. |
| Escudo com visto e texto de marketing | Sinal geométrico original. Textos factuais, sem promessas ("Protege o teu PC" não existe). |
| Cantos muito redondos, espaçamento uniforme sem hierarquia | Raio de 2 px. Dois ritmos de espaçamento (dentro e entre) e escala tipográfica com títulos e corpo bem distintos. |
| Animações sem função | Só a barra de progresso. Nada mais se move. Respeita a definição de reduzir animações. |

As capturas de ecrã a 100% e a 150%, geradas pelo CI Windows e guardadas como artefactos (`zerobirus-screenshots`), servem para rever isto sobre a interface real.

## 5. Tokens

<!-- generated:tokens:start -->
| Token | Valor |
| --- | --- |
| `paper` | `#F5F2EA` |
| `surface` | `#FCFBF8` |
| `ink` | `#1C1A17` |
| `ink_muted` | `#57534B` |
| `rule` | `#8C8677` |
| `rule_soft` | `#D8D3C6` |
| `selection` | `#DCE8EC` |
| `accent` | `#0B5C73` |
| `accent_hover` | `#084A5D` |
| `on_accent` | `#FFFFFF` |
| `suspeito` | `#9B1B1B` |
| `suspeito_bg` | `#F6E3E0` |
| `conferir` | `#7A4B00` |
| `conferir_bg` | `#F4EAD0` |
| `ok` | `#25623A` |
| `ok_bg` | `#E1EEE3` |
| `nao_verificado` | `#4B4F59` |
| `nao_verificado_bg` | `#E6E7EA` |
| `danger` | `#9B1B1B` |
| `on_danger` | `#FFFFFF` |
| `disabled` | `#6B665C` |
| `font_body_pt` | `10.0` |
| `font_small_pt` | `9.0` |
| `font_title_pt` | `16.0` |
| `font_subtitle_pt` | `12.0` |
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
| `focus_width` | `2` |

Contrastes (WCAG, mínimo 4.5:1 para texto e 3:1 para elementos sem texto):

| Par | Rácio | Onde |
| --- | --- | --- |
| `ink` sobre `paper` | 15.52 | body text on the page |
| `ink` sobre `surface` | 16.78 | table and text areas |
| `ink_muted` sobre `paper` | 6.84 | secondary text on the page |
| `ink_muted` sobre `surface` | 7.40 | secondary text in tables |
| `ink` sobre `selection` | 13.89 | selected row |
| `on_accent` sobre `accent` | 7.52 | primary button |
| `on_accent` sobre `accent_hover` | 9.78 | primary button hovered |
| `accent` sobre `paper` | 6.72 | links and accent text |
| `on_danger` sobre `danger` | 8.18 | destructive button |
| `suspeito` sobre `paper` | 7.31 | level text |
| `suspeito` sobre `suspeito_bg` | 6.62 | level text on its tint |
| `conferir` sobre `paper` | 6.62 | level text |
| `conferir` sobre `conferir_bg` | 6.18 | level text on its tint |
| `ok` sobre `paper` | 6.50 | level text |
| `ok` sobre `ok_bg` | 6.08 | level text on its tint |
| `nao_verificado` sobre `paper` | 7.33 | level text |
| `nao_verificado` sobre `nao_verificado_bg` | 6.63 | level text on its tint |
| `disabled` sobre `paper` | 5.10 | disabled text |
| `rule` sobre `paper` | 3.24 | borders of inputs and tables |
| `accent` sobre `paper` | 6.72 | focus ring |
<!-- generated:tokens:end -->
