# Plano novo: ZeroBirus depois do Alpha 1.0

O BRIEF (docs/BRIEF.md) continua a ser a especificação de base e as suas regras não se negoceiam. Este plano acrescenta uma segunda face ao produto, pedida pelo João depois do primeiro teste em Windows real.

## Ideia

Uma só aplicação com um **ecrã inicial em forma de menu clicável**. Cada opção é um cartão grande:

1. **Limpeza** (lixo, caches, temporários)
2. **FPS / Modo jogo**
3. **Arranque** (programas que arrancam com o Windows)
4. **Atualizar apps** (winget)
5. **Drivers**
6. **Análise profunda** (o que já existe, as 7 etapas: contexto, verificação, diagnóstico, autorização, remoção, confirmação, depois). É a **última opção, no fundo do menu**, num cartão mais largo e mais cuidado (é a que distingue o ZeroBirus de um limpador qualquer).

Os cinco primeiros são o modo simples, para gamers e dia a dia: um botão grande "Analisar", números claros ("podes libertar 6,4 GB"), categorias com caixas, um toque para limpar, e no fim "libertaste X GB". Pouco texto, nada de jargão. Inspirado no que torna a limpeza do Xiaomi boa: **simples à frente, engenharia por trás** (tamanhos reais, seguro por omissão, tudo reversível). A análise profunda só recebe correções.

## Categorias do modo simples

| Categoria | O que faz | Como (engenharia) |
| --- | --- | --- |
| **Limpeza de lixo** | Temporários do utilizador, caches de navegadores (só cache), miniaturas, relatórios de falhas do utilizador, caches de shaders (DirectX, NVIDIA, AMD), registos antigos. Mostra o tamanho por categoria. | Lista só locais do utilizador, nunca ficheiros do Windows; passa pelo mesmo motor (plano autorizado, quarentena, desfazer, verificação). |
| **FPS Booster / Modo jogo** | Perfil reversível para jogar: plano de energia de alto desempenho, Modo de Jogo do Windows, lista de programas em segundo plano que podes fechar enquanto jogas, desligar a captura da Xbox Game Bar (opcional). Botão "Ativar" e "Repor". | Cada alteração guarda o valor anterior e verifica depois; "Repor" desfaz tudo. Sem "limpadores de RAM" nem promessas de percentagem de FPS: mostramos antes e depois (RAM livre, processos) e dizemos que o ganho depende do PC. |
| **Otimizador de arranque** | Programas que arrancam com o Windows, com o impacto, e desativar os que não queres. | Reutiliza a leitura de arranque que já existe; desativar é reversível. |
| **Atualizador de apps (winget)** | Lista o que tem atualização e atualiza as que escolheres, ou todas. | Chama o `winget` do Windows (caminho absoluto); o ZeroBirus não faz pedidos de rede por si. Ver decisão em aberto 1. |
| **Drivers** | Lista a versão e a data dos drivers (placa gráfica, rede, áudio) e leva-te às páginas certas: Windows Update (opcionais) e a página do fabricante (NVIDIA, AMD, Intel) conforme a placa detetada. | Só leitura e ligações. Não descarrega nem instala drivers (risco de cadeia de fornecimento e de ecrã preto). |
| **Espaço em disco** (analítico) | Maiores pastas e ficheiros, só leitura. | No modo profundo, para quem percebe. |

## Visual

Escuro por omissão, acento ciano/verde-elétrico, números grandes em tipo monoespaçado, anéis de progresso, cartões com cantos suaves, sem néon exagerado. Mantém tudo o que o DESIGN.md já exige: funciona a 150% em 1280x720, teclado, alto contraste do Windows, animações reduzidas. O DESIGN.md é atualizado **antes** do código.

## Fases (cada uma para e é revista)

| Fase | Conteúdo | Aceitação |
| --- | --- | --- |
| **6. Ecrã inicial e tema** | Atualizar DESIGN.md; ecrã inicial com o menu de cartões (a análise profunda por último, no fundo); tema escuro gamer; Autorização com grupos que se abrem e fecham (feedback do primeiro teste). | Capturas a 100% e 150% revistas; CI verde. |
| **7. Limpeza de lixo** | Categorias com tamanhos, um toque para limpar, ecrã de resultado ("libertaste X GB"), tudo pelo motor existente. | Teste de integração no Windows; teste manual do João. |
| **8. Modo jogo e arranque** | Operações reversíveis novas no motor (valor de registo, plano de energia, desativar arranque), perfil "Ativar/Repor", gestor de arranque. Auditoria adversarial. | Integração Windows com desfazer; auditoria em docs/reviews. |
| **9. Atualizador e drivers** | winget (lista, atualizar escolhidas) e a página de drivers. | Teste manual do João. |
| **10. Release 1.1** | Instalador opcional, assinatura de código (SignPath), formulário de falsos positivos da Microsoft. | Teste manual completo. |

## Regras que continuam (BRIEF, secção 4 e CLAUDE.md)

Nada altera o sistema sem um plano autorizado; tudo é reversível e verificado a reler o estado; nunca tocar em ficheiros do Windows; nunca desativar um antivírus; tudo o que vem do sistema é dado; sem telemetria; "testado em Windows" só com CI verde ou confirmação do João.

## Decisões em aberto (do João)

1. **winget e a rede.** A regra "zero pedidos de rede no código do produto" mantém-se: quem descarrega é o `winget`, não o ZeroBirus. Mas o produto passa a precisar de internet para esta função, que fica **opcional e separada**, só quando carregas no botão. Recomendo aceitar assim. Se não, o atualizador só mostra o que tem atualização e abre o winget.
2. **Libertar espaço de verdade.** A quarentena duplica o espaço até apagares. Recomendo manter a regra e ter, no fim da limpeza, o botão "Libertar já" (o "Apagar a quarentena de vez" que já existe, com confirmação). A alternativa, apagar logo caches que se regeneram sozinhas (cache de shaders e do navegador), quebra uma regra do BRIEF e precisa da tua decisão.
3. **Âmbito do Modo jogo.** Recomendo só alterações reversíveis e pequenas (plano de energia, Modo de Jogo, Game Bar, programas em segundo plano). Tweaks agressivos de registo e serviços ficam de fora.
