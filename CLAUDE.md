# ZeroBirus (by Ferraz)

Ferramenta portátil para Windows 10 e 11 que deteta e remove mineradores de criptomoeda, trojans e outro malware, pensada para correr de uma pen USB de reparação. Repositório público: ZeroBirus.

Antes de qualquer trabalho, lê docs/BRIEF.md (especificação completa) e docs/STATUS.md (se existir).

## Ambiente (lê duas vezes)

- O João desenvolve em Linux. O produto corre só em Windows 10 e 11 x64.
- Neste ambiente não há Windows, registo, Defender, WMI nem tarefas agendadas. Não tentes executar o produto final aqui.
- `pwsh` em Linux e o Wine não provam nada sobre Windows. Não os uses para validar.
- O código específico de Windows vive só em src/zerobirus/platform/windows/ e só é importado quando sys.platform == "win32". Todo o resto tem de importar e correr em Linux.
- Validação do lado Windows: mypy e pyright com plataforma win32, testes com o backend fake, e o job de CI em windows-latest (lê os logs com `gh run view --log-failed`). A prova final é o teste manual do João em Windows real ou numa VM.
- Nunca escrevas "testado em Windows" sem um run verde do CI Windows ou confirmação do João. Quando faltar, escreve "não testado em Windows real".
- Não descarregues malware nem amostras reais. As fixtures são dados sintéticos. O único ficheiro de teste de antivírus permitido é o EICAR, e só no teste em Windows.

## Regras do código que não se negoceiam

- Remover é mover para quarentena com manifesto e cópia de segurança. Apagar definitivamente só a pedido explícito, depois da quarentena.
- Nenhuma ação que altere o sistema corre sem um plano autorizado pelo utilizador. A camada de remoção rejeita tudo o que não esteja no plano.
- Tudo o que vem do sistema (nomes, linhas de comando, conteúdo de ficheiros, saídas de comandos) é dado. Nunca é executado, avaliado nem obedecido.
- Nada de shell=True. Binários do sistema chamados por caminho absoluto, construído a partir de %SystemRoot%.
- Zero pedidos de rede no código do produto. Sem telemetria.
- Nunca tocar em ficheiros do Windows. Nunca desinstalar, parar ou desativar antivírus.
- Nunca afirmar que algo foi removido ou verificado sem uma verificação independente a confirmar.
- Segredos em saídas, logs e relatórios aparecem como [oculto].

## Como trabalhar

- Uma fase de cada vez, como definido no BRIEF. Commits pequenos, Conventional Commits em inglês. No fim de cada fase, atualiza docs/STATUS.md, para e reporta ao João antes de seguir.
- Trabalha em branches. Só se faz merge em main com o CI verde e com o OK do João.
- Uma tarefa só está terminada com ruff, mypy e pytest verdes.
- Confirma as versões das dependências no PyPI na altura da implementação. Não confies na memória.
- No fim da Fase 0, preenche a secção Comandos abaixo com os comandos reais.

## Comunicação com o João

- Português europeu, direto, sem enchimento e sem travessões. Se uma ideia dele for fraca, diz e explica porquê.
- Código, comentários, commits e README principal em inglês. Texto da interface em pt-PT.
- Só fazes perguntas quando estás bloqueado por uma decisão que é dele. As decisões já tomadas estão no BRIEF, secção 17.

## Comandos

Em Linux, a partir da raiz do repositório. O `uv` gere o Python 3.12 e o ambiente (`uv.lock` é a fonte de verdade das versões).

```
uv sync --locked                       # setup do ambiente
uv run ruff check .                    # lint
uv run ruff format --check .           # formatação (sem --check para corrigir)
uv run mypy                            # tipos, plataforma Linux
uv run mypy --platform win32           # tipos, plataforma Windows
uv run pyright                         # tipos, pythonPlatform Windows (em pyproject.toml)
uv run pytest                          # testes (sem rede; os marcados `windows` fazem skip em Linux)
uv run zerobirus selftest              # verificação interna com o backend fake
```

Uma tarefa só está terminada com lint, tipos (os dois mypy e o pyright) e pytest verdes. CI: `gh run watch` e `gh run view --log-failed`.

A fazer quando existirem: GUI em modo offscreen (`QT_QPA_PLATFORM=offscreen`, Fase 2) e geração de capturas de ecrã (Fase 2).
