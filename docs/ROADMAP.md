# Plano: ZeroBirus depois do Alpha 1.0

O BRIEF (docs/BRIEF.md) continua a ser a especificação de base e as suas regras não se negoceiam. Este plano substitui a versão anterior (modo simples com cinco cartões) pela estrutura pedida pelo João depois de ver as capturas da Fase 6.

## Estrutura

Um **menu principal** com 3 cartões. Cada cartão abre **uma janela própria**. Dentro de cada janela há os seus módulos, e os módulos com muitas opções têm um submenu próprio.

```
Menu principal
├── Modo Jogo
│   ├── FPS Optimizer      tudo o que rende FPS
│   ├── RAM Lover          diagnóstico simples da RAM e otimização
│   └── MegaTweaker        submenu próprio (muitas opções, organizadas por categoria)
├── PitStop                (nome proposto: a paragem na box do PC, para afinar e preparar)
│   ├── FirstSetup         submenu próprio (estilo Ninite)
│   ├── AllUp              atualizar apps e serviços (estilo winget)
│   ├── BigDiag            submenu próprio (relatório completo do PC)
│   └── AllDrivers         drivers com atualização disponível
└── Nerd'O                 a análise profunda que já existe (7 etapas), sem "modos"
```

Notas de organização:

- A **Limpeza** deixa de ser um cartão: lixo e temporários só existem no Nerd'O, num grupo próprio "Arquivos Temporários" (ver abaixo).
- O **Arranque** (programas que arrancam com o Windows) passa para o MegaTweaker, que reutiliza a leitura que já existe.
- O Nerd'O é o fluxo atual de 7 etapas. Recebe só as alterações do diagnóstico descritas a seguir.
- Cada janela usa o mesmo tema, a mesma barra lateral e o mesmo motor (plano autorizado, quarentena ou valor anterior guardado, desfazer, verificação independente).

## Diagnóstico do Nerd'O: tabela de risco

Cinco níveis, do mais leve ao mais grave. O nível sai da pontuação existente (`core/rules/*.json`); os limiares ficam em ficheiro de regras, com testes golden.

| Nível | O que significa | Ação por omissão |
| --- | --- | --- |
| 1. **Incomum** | Fora do normal mas explicável (programa raro, caminho pouco habitual). Um sinal fraco. | Só informar. Sem remoção sugerida. Fica desmarcado. |
| 2. **Anómalo** | Vários sinais fracos ou um comportamento estranho. | Informar e guardar na base de comparação para a próxima verificação. Desmarcado. |
| 3. **Suspeito** | Pelo menos um sinal forte, sem confirmação. | Recomenda análise do Defender e revisão manual. Remoção disponível, desmarcada. |
| 4. **Grave** | Sinais fortes concordantes de um tipo de ameaça. | **Marcado por omissão** para quarentena. |
| 5. **Crítico** | Confirmado por sinais independentes (por exemplo, minerador a correr, persistência e ligação a pool). | **Marcado por omissão** para quarentena, com ponto de restauro e fecho do processo antes. |

Regras:

- O utilizador pode desmarcar qualquer item "por sua conta e risco" (texto curto e claro na interface). Marcado por omissão nunca significa executado sem autorização: o plano continua a ter de ser autorizado.
- O `safety` manda sempre. Um item protegido (Windows, antivírus, pastas pessoais) nunca é removível, seja qual for o nível. Um item só chega a Crítico com sinais independentes; a pontuação não sobe só porque o nome assusta.
- Remover continua a ser mover para a quarentena. Nada de apagar por omissão.
- **Sinalização**: em vez do semáforo atual, cada incidente tem um selo de nível (cor e palavra, nunca só cor), e a lista fica agrupada por nível, do Crítico para o Incomum. Cada grupo é recolhível (já existe `CollapsibleGroup`). Cabeçalho do grupo: contagem e quantos estão marcados.
- **Arquivos Temporários**: grupo próprio, recolhível, fora da tabela de risco. Só aparece no Nerd'O, desmarcado por omissão, passa pela quarentena como tudo o resto.

## Modo Jogo

Todas as alterações são reversíveis (valor anterior guardado, verificado a reler, botão "Repor"), com ponto de restauro antes.

- **FPS Optimizer**: plano de energia de alto desempenho, Modo de Jogo do Windows, desligar a captura da Xbox Game Bar, agendamento de GPU por hardware se suportado, programas em segundo plano que podes fechar enquanto jogas. Mostra antes e depois (RAM livre, processos). Sem promessas de percentagem de FPS: o ganho depende do PC.
- **RAM Lover**: diagnóstico simples (total, em uso, cache, os maiores consumidores, pressão de memória) e otimização: fechar o que escolheres e esvaziar a lista de espera (standby) quando faz sentido. Sem "limpadores de RAM" milagrosos: mostra o que mudou de facto.
- **MegaTweaker**: submenu próprio, categorias à maneira do winutil (inspiração; reimplementamos, não copiamos código). Cada tweak tem descrição, nível (seguro, moderado, agressivo), estado atual e "Repor". Exemplos: telemetria e recomendações do Windows, animações, serviços desnecessários em PCs de jogo, arranque. Fora de qualquer nível, sempre: tudo o que toca em antivírus, Defender, Windows Update de segurança, firewall e ficheiros do Windows.

## PitStop

- **BigDiag**: relatório de diagnóstico completo, só leitura: resultado do MRT, RAM, discos (SSD e SMART), CPU, GPU, temperaturas quando disponíveis, estado do Defender, últimas falhas, espaço. Exporta para ficheiro redigido (sem dados pessoais).
- **AllUp**: lista o que tem atualização e atualiza as escolhidas ou todas, chamando o `winget` do Windows por caminho absoluto.
- **FirstSetup**: ecrã igual ao Ninite, com as mesmas categorias (Web Browsers, Messaging, Media, Developer Tools, Compression, Utilities, Other, etc.). Escolhes as apps e o ZeroBirus gera um executável no ambiente de trabalho com a marca ZeroBirus que instala tudo de seguida.
- **AllDrivers**: lista drivers com atualização disponível. Ver decisão 2.

## Fases (cada uma para e é revista)

| Fase | Conteúdo | Aceitação |
| --- | --- | --- |
| **6. Ecrã inicial e tema** (feita, PR aberto) | Tema escuro, cartões, grupos recolhíveis na Autorização. | Capturas revistas; CI verde. |
| **7. Reorganização** | DESIGN.md primeiro. Menu principal com 3 cartões e janelas por módulo (esqueleto, módulos "Em breve"). Nerd'O: tabela de risco de 5 níveis, novo sinal de seleção (Grave e Crítico marcados), grupo "Arquivos Temporários". | Golden tests dos níveis; capturas a 100% e 150%; CI verde. |
| **8. Modo Jogo (FPS Optimizer e RAM Lover)** | Operações reversíveis novas no motor (valor de registo, plano de energia, fecho de processo), "Repor". Auditoria adversarial. | Integração Windows com desfazer; auditoria em docs/reviews. |
| **9. MegaTweaker** | Catálogo de tweaks por categoria e nível, submenu próprio, ponto de restauro, "Repor" por tweak e total. Auditoria. | Integração Windows; teste manual do João. |
| **10. PitStop (BigDiag e AllUp)** | Relatório completo e atualizador winget. | Teste manual do João. |
| **11. FirstSetup e AllDrivers** | Dependem das decisões 1 e 2. | Depois das decisões. |
| **12. Release 1.1** | Instalador opcional, assinatura de código (SignPath), formulário de falsos positivos da Microsoft. | Teste manual completo. |

## Regras que continuam (BRIEF, secção 4 e CLAUDE.md)

Nada altera o sistema sem um plano autorizado; tudo é reversível e verificado a reler o estado; nunca tocar em ficheiros do Windows; nunca desativar um antivírus; tudo o que vem do sistema é dado; sem telemetria; "testado em Windows" só com CI verde ou confirmação do João.

## Decisões em aberto (do João)

Estas três bloqueiam a Fase 11 e o âmbito da Fase 9. As Fases 7 e 8 não dependem delas.

1. **FirstSetup e a rede.** Um executável "como o Ninite" tem de descarregar instaladores, e o CLAUDE.md diz "zero pedidos de rede no código do produto". Recomendo: o executável gerado chama o `winget` (quem descarrega é o Windows, de uma fonte assinada pela Microsoft), e o ZeroBirus em si continua sem rede. Copiar o Ninite à letra (instaladores diretos dos sites dos fabricantes) obriga a manter links e somas de verificação de dezenas de apps, partem a cada versão, e abre a porta a instaladores trocados. Se aceitares o winget, o ecrã e as categorias ficam iguais ao Ninite; só muda o motor por trás.
2. **AllDrivers.** Recomendo **não** instalar drivers fora do Windows Update: drivers de sites de terceiros são um risco de cadeia de fornecimento e de ecrã preto. Versão proposta: listar versão e data, mostrar o que o Windows Update tem como opcional e instalar por aí, mais a ligação à página do fabricante (NVIDIA, AMD, Intel) para a placa gráfica. Não faz "atualizar tudo num clique" com ficheiros de terceiros.
3. **Âmbito do MegaTweaker.** A decisão anterior era só mudanças pequenas e reversíveis. O MegaTweaker alarga isto. Recomendo aceitar com estas condições: ponto de restauro antes, cada tweak reversível por valor anterior guardado, nível "agressivo" desligado por omissão e com aviso, e a lista negra acima (antivírus, Defender, atualizações de segurança, firewall, ficheiros do Windows).

Nota sobre a ideia: a estrutura em 3 janelas é boa e cabe no motor que já existe. O ponto fraco é o FirstSetup à Ninite, pela razão da decisão 1; o resto é trabalho, não risco.
