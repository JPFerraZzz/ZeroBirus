# STATUS

Três níveis de teste, nunca confundidos:

- **Linux**: ruff, mypy (linux e win32), pyright (Windows), pytest com backend fake.
- **CI Windows**: job `windows` em windows-latest.
- **Manual (João)**: Windows real ou VM, segundo docs/WINDOWS_TEST_PLAN.md (ainda não existe).

## Fase 0: base

Estado: fechada. Fase 0 (PR #1) e endurecimento com auditoria (PR #2) fundidos. Ver `docs/reviews/phase-0-audit.md`.

### Feito

- Esqueleto do repositório conforme BRIEF §7, pyproject, `uv.lock`, Python 3.12.
- `core/models`, `core/safety`, `core/redact`, `platform/base` (Inspector e Remediator como Protocol), backend fake com fixture "PC limpo", CLI `version` e `selftest`.
- Testes: models, safety (exemplos e hypothesis), redact, backend fake, CLI, política (sem shell=True, sem APIs Windows fora de platform/windows, sem Remediator em core/scanners, sem módulos de rede), codificação dos .ps1 (ASCII ou UTF-8 com BOM).
- `.gitattributes` com LF por omissão.
- CI Ubuntu e Windows, actions fixadas por SHA, permissões mínimas, Dependabot.
- LICENSE, README.md, README.pt-PT.md, SECURITY.md.

### Hardening e auditoria (PR #2, fundido)

- `SystemContext` com campos obrigatórios e validados; proteção de processos por nome mais caminho, nunca por assinatura.
- Auditoria adversarial de `safety` e `redact` (relatório em `docs/reviews/phase-0-audit.md`): 32 problemas encontrados e corrigidos, incluindo um ReDoS quadrático em `redact`.
- mutmut local (grupo `mutation`, fora do CI): 597 de 598 mutantes mortos, o sobrevivente é equivalente. Hypothesis perfil `deep`: sem contraexemplos.
- Testes de política com detetores puros e casos sintéticos de violação.
- O `# STATUS` não estava repetido no ficheiro; o ponto A1 não precisou de correção.

### Onde foi testado

| Item | Linux | CI Windows (PR #2) | Manual (João) |
| --- | --- | --- | --- |
| ruff, mypy (linux e win32), pyright | verde | mypy verde (ruff e pyright só correm no Ubuntu) | não aplicável |
| pytest (unit, política, encoding) | verde (519 passed, 4 skipped, 1 xfailed) | verde (522 passed, 1 skipped, 1 xfailed) | não testado |
| testes marcados `windows` (4) | skipped por desenho | verde (4 passed) | não testado |
| `zerobirus version` e `selftest` | verde | verde | não testado |

O skip no Windows é `test_windows_backend_not_imported_off_windows`, que só faz sentido fora do Windows.

Nada disto foi testado em Windows real (só no runner windows-latest). Todo o `core/safety` trabalha só sobre strings, por isso a correspondência com o comportamento real do Windows (por exemplo, como o Windows trata `C:\Windows\ \x`) só se confirma no CI Windows e no teste manual.

### Pendentes e decisões a registar

- **Caminhos canónicos (obrigatório para o backend Windows, Fase 1)**: `core/safety` só compara strings. O backend tem de lhe entregar caminhos canónicos obtidos com `GetFinalPathNameByHandle` (resolve links, nomes 8.3 e maiúsculas), nunca o texto cru vindo de um processo ou do registo. Sem isto, as garantias de `safety` não valem.
- **Decisão pendente do João: `C:\Windows\Temp`**: hoje fica inteiramente protegido (tudo sob `%SystemRoot%`), mas é onde o malware costuma cair. Decidir se há uma exceção explícita (por exemplo só ficheiros executáveis sem assinatura em `C:\Windows\Temp`), sabendo que o BRIEF §8 manda não mexer em `C:\Windows`.
- **Assinatura inválida em binário de sistema**: feito na Fase 1 (Finding SUSPEITO que recomenda a Análise offline do Defender, nunca remoção).
- **`SystemContext`**: todos os campos de localização são obrigatórios. `personal_folders` tem de vir de SHGetKnownFolderPath (OneDrive e nomes localizados como "Ambiente de Trabalho"); o `safety` não os adivinha, e há um teste a provar que sem eles a pasta NÃO fica protegida.

- **Program Files**: resolvido na Fase 1 (protegido por assinatura, ver abaixo).
- **Segmentos ambíguos**: caminhos com segmentos só de pontos ou espaços a meio (`C:\Windows\ \x`) são tratados como protegidos (falham fechado), porque o Windows é ambíguo. Encontrado por hypothesis.
- **Nomes 8.3**: um caminho com `~N` num componente é tratado como protegido. O backend tem de resolver o nome longo antes.
- **Redact**: hex puro de 64 caracteres sem nome ao lado não é redigido (é indistinguível de um SHA-256). Documentado em SECURITY.md.
- **UNC e raízes de unidade**: sempre protegidos.
- Ainda não existem: docs/ARCHITECTURE.md, DETECTION.md, DESIGN.md, WINDOWS_TEST_PLAN.md, modelos de issue, lock com hashes verificado em CI além de `--locked`.
- `psutil` entrou na Fase 1. PySide6 entra na Fase 2.

## Fase 1: leitura

Estado: **fechada no código; falta só o teste manual do João** (`docs/WINDOWS_TEST_PLAN.md`). PR #4 fundido em main depois do CI verde (Ubuntu, Windows e build do executável). O PR #3 (preâmbulo: suíte removível, teste diferencial e dados reais do psutil) foi fundido pelo João a 2026-10-26.

### Feito

Preâmbulo (PR #3, fundido):

- (a) Suíte "tem de ser removível" (24 casos): sem alterações ao `safety`.
- (b) Teste diferencial só de leitura no CI Windows (18 grafias exóticas de 5 ficheiros reais): nenhuma hipótese do audit foi contradita. Resultados em `docs/reviews/phase-0-audit.md`.
- (c) Dados reais do psutil: System (PID 4) vem sem caminho; Registry vem com o texto `Registry`.

Ajustes pedidos nesta ronda:

- **Registry**: um "caminho" igual ao nome do processo e sem separadores é tratado como "sem imagem" (`is_bare_image_name`), por isso a proteção vem da regra do nome e não do fallback de caminho não canónico. Teste com o dado gravado e prova de que o fallback não é consultado.
- **Memory Compression**: `tests/fixtures/recorded/` e `tests/unit/test_recorded_machines.py` estão preparados para fixtures gravadas em máquinas reais. O teste faz skip até existir uma (ver skips).
- **`scan --json --out ficheiro`**: o relatório sai redigido (segredos como `[oculto]`) e sem dados pessoais (nomes de utilizador, conteúdo de pastas pessoais), com a secção `snapshot` que serve de fixture. `docs/WINDOWS_TEST_PLAN.md` (versão da Fase 1) descreve a verificação em Windows real, o que anotar e como gerar fixtures golden com `tools/report_to_fixture.py`.

Fase 1 propriamente dita:

- `safety`: Program Files passa a ser protegido por assinatura (Microsoft ou fabricante de antivírus; assinatura desconhecida continua a falhar fechado; pastas do Defender e as geridas pelo Windows protegidas sempre). O `xfail` foi removido.
- Modelos, `Snapshot` (esquema único para backend, fixtures e relatório), contrato do `Inspector` com `Observed` (o que se viu mais as lacunas), `RecordingInspector` (uma pergunta ao backend por pesquisa, mesmo com verificações em paralelo).
- Pontuação aditiva e explicável com pesos em `core/rules/*.json`, heurísticas puras, diagnóstico (tipo de ameaça, certeza, por onde pode ter entrado, coisas normais que assustam). Regras do João: a pontuação usa sempre a linha de comando original e o `redact` só se aplica à saída. Teste a provar `stratum+tcp://utilizador:segredo@pool.exemplo:3333`: servidor e porta visíveis, palavra-passe oculta. Teste de política: nenhum módulo de pontuação importa `core.redact`.
- Nove verificações (`scanners/`), cada uma com timeout próprio e em paralelo; falha ou excesso de tempo dão NAO_VERIFICADO com motivo.
- CLI `scan [--json] [--out FILE] [--demo NOME] [--fixture FICHEIRO]`.
- Backend Windows só de leitura: `winreg`, `psutil`, `ctypes`, e uma única ponte PowerShell (caminho absoluto, `-EncodedCommand`, dados como JSON em stdin, `PSModulePath` fixo). Parsers puros em `core/parsing.py`, testados em Linux.
- Fixtures sintéticas (clean_pc, miner_pc, false_positives_pc, no_admin_pc) e golden tests com as expectativas escritas por extenso.
- `tools/windows/make_test_artifacts.ps1` e `remove_test_artifacts.ps1` e o teste de integração só de deteção.
- `docs/DETECTION.md` (tabela de sinais gerada e testada contra `scoring.json`).

### Ronda de endurecimento (autonomia total)

- **URLs no redact:** política única (D-001 em `docs/DECISIONS.md`). Utilizador ou carteira de URLs stratum ficam visíveis e vão para `indicators` no relatório; palavras-passe sempre ocultas; utilizador e palavra-passe de outros esquemas ocultos.
- **Indicadores de mineração:** verificados contra fontes públicas (XMRig, MITRE T1496, regra Sigma, repositórios dos mineradores, sites dos pools) com URL e data em `docs/DETECTION.md`. Sem fonte: "não verificado", sinais fracos, nunca SUSPEITO sozinho. Só a porta 3333 ficou verificada; as outras portas de pools ficam não verificadas.
- **Perfis sem sessão:** uma linha agrupada NAO_VERIFICADO; issue #5 para ler hives offline na v1.1.
- **Ponte PowerShell:** ambiente construído de raiz, `system_root` só de `GetSystemWindowsDirectoryW`, scripts com erro por item, saída limitada a 32 MB, stderr redigido, lotes de 200 (D-004). `-EncodedCommand` mantido; o que observar no teste manual está no plano.
- **Build de desenvolvimento:** job "Windows dev build" do CI (PyInstaller `--onedir`, `--uac-admin`, versão com fabricante Ferraz, ZIP e SHA-256 como artefacto, smoke test do `.exe`).

### O que o runner Windows real ensinou (corrigido, com teste Linux)

Primeira corrida do backend real em windows-latest:

1. O `PSModulePath` herdado do PowerShell 7 impedia o módulo de segurança de carregar: todas as assinaturas vinham desconhecidas. Corrigido com um `PSModulePath` fixo. Também fecha a porta a um `PSModulePath` hostil.
2. Um processo a terminar durante a leitura fazia falhar a verificação inteira (`NoSuchProcess`). Passa a ser ignorado.
3. Exclusões do Defender sobre unidades inteiras (`C:\`, `D:\`) marcavam todos os ficheiros e davam SUSPEITO a MsMpEng. Uma exclusão de unidade é agora um achado só, e o sinal forte exige pasta gravável.
4. Pastas `{GUID}` de `ProgramData\Package Cache` contavam como "nome aleatório". Deixaram de contar. `.msi` deixou de ser candidato.
5. Valores vazios do PowerShell (`['']`) eram lidos como exclusões. Filtrados.
6. A pesquisa dirigida gastava os 25 s em ProgramData e nunca chegava a AppData: falhou a deteção do artefacto de teste. Agora cada pasta recebe uma parte justa do orçamento, as mais prováveis primeiro, e uma paragem antecipada diz qual pasta ficou por ver.
7. O PowerShell deixa `__PSScriptPolicyTest_*.ps1` em Temp: ignorado, e documentado como efeito do Windows.
8. Três coisas de redação: "Coisas normais que assustam" agrupa processos iguais; só se nomeia um tipo de ameaça com pelo menos um sinal forte ou três fracos; exclusão de unidade inteira tem texto próprio.

Resultado numa máquina real limpa (runner): nenhum SUSPEITO. Os CONFERIR que sobram são legítimos do runner (serviços de desenvolvimento sem assinatura, tarefas do agente do GitHub em ProgramData, uma linha do hosts, Defender com tempo real desligado, exclusões de `C:\` e `D:\`).

### Onde foi testado

| Item | Linux | CI Windows (PR #4) | Manual (João) |
| --- | --- | --- | --- |
| ruff, mypy (linux e win32), pyright | verde | mypy verde (ruff e pyright só correm no Ubuntu) | não aplicável |
| pytest unit e golden | verde (1205 passed, 52 skipped) | verde (1249 passed, 8 skipped, run 40416781291) | não testado |
| testes marcados `windows` (47) | skipped por desenho | verde (46 passed, 1 skipped: Memory Compression) | não testado |
| Backend Windows (registo, serviços, processos, ligações, tarefas, Defender, WMI, assinaturas, pesquisa de ficheiros) | só os parsers | verde no runner windows-latest | **não testado em Windows real** |
| Artefactos inofensivos: deteção, nada alterado, limpeza | não aplicável | verde | não testado |
| `zerobirus scan --json --out` com o backend real | não aplicável | verde | não testado |
| Máquina com vários perfis, outro antivírus, jogos, Windows noutro idioma | não aplicável | não coberto (o runner é uma máquina limpa) | **por fazer, ver `docs/WINDOWS_TEST_PLAN.md`** |

Auditorias locais depois das alterações ao `safety`: `mutmut` sobre `safety.py` e `redact.py`: 643 mutantes, 641 mortos, 2 sobreviventes, ambos equivalentes (`rstrip("XX .XX")` numa chave que nunca tem `X` maiúsculo, e `path = ""` em vez de `path = None`, que o código trata de igual maneira). Hypothesis com o perfil `deep` (5000 exemplos): sem contraexemplos.

### Testes em skip no CI, e porquê

| Teste | Onde | Motivo |
| --- | --- | --- |
| `test_recorded_kernel_pseudo_processes_are_protected[System]`, `[Registry]`, `[Memory Compression]` | ambos | Não há ainda nenhuma fixture de uma máquina real em `tests/fixtures/recorded/`. O João fornece-as no teste manual. |
| `test_there_are_recorded_fixtures_to_replay` e `test_recorded_machine_gives_the_recorded_verdicts` (conjunto de parâmetros vazio) | ambos | O mesmo: nenhuma fixture `*.expected.json` gravada. |
| `test_kernel_pseudo_processes_...[Memory Compression]` (psutil real) | Windows | O runner windows-latest não tem esse processo. |
| `test_windows_backend_not_imported_off_windows`, `test_cli_scan_without_demo_refuses_off_windows` | Windows | Só fazem sentido fora do Windows. |
| Todos os marcados `windows` | Linux | Por desenho, só correm em Windows. |

Não há skips por Defender: no runner o Defender responde (tempo real desligado, com exclusões de `C:\\` e `D:\\`), por isso o estado e as exclusões foram lidos. O caso "Defender inativo ou ausente" é coberto em Linux com o backend fake (estado não lido dá NAO_VERIFICADO, nunca OK). No teste de integração, o Defender e a tarefa agendada de teste fazem skip se o runner não os deixar criar; não aconteceu.

### Decisões e pontos em aberto

- **URL com credenciais**: o `redact` da Fase 0 mantém o nome de utilizador de `utilizador:segredo@servidor` visível e esconde só a palavra-passe. Para URLs de pools o utilizador costuma ser a carteira. Se preferires esconder também o utilizador, diz-me; muda um padrão e um teste.
- **Fontes dos indicadores de mineração**: as listas (nomes, marcas, portas, pools) vêm de conhecimento geral e **não foram confirmadas numa fonte online** nesta sessão. Estão assim declaradas em `docs/DETECTION.md`. Cada entrada precisa de ser verificada e referenciada antes da primeira release.
- **Perfis sem sessão**: não se monta nenhum hive (seria alterar o registo). Em PCs com vários perfis a verificação de arranque fica NAO_VERIFICADO com o nome dos perfis por ler. Se achares isto demasiado ruidoso, a alternativa é só avisar.
- **Cache de assinaturas**: só dentro de uma execução. A cache por caminho, data e tamanho do BRIEF §9 entre execuções fica para depois (nada a persistir na Fase 1).
- **Ladrão de palavras-passe e publicidade**: sem sinais próprios na v1. Um SUSPEITO que não é explicado por minerador nem por trojan aparece como "Ameaça não classificada", com o aviso de que esta versão não distingue esses tipos; nunca é forçado a uma categoria existente. Por isso `system_binary_bad_signature` e `system_name_wrong_location` deixaram de apontar para "trojan".
- **Exclusão do Defender sobre unidade inteira**: sozinha é CONFERIR com texto próprio. Combinada, na mesma máquina, com persistência para AppData ou Temp (já CONFERIR ou pior, por isso um programa conhecido e assinado não conta), ligação a porta de mineração, linha de comando de mineração ou nome de minerador, sobe para SUSPEITO. Persistência em ProgramData sozinha não conta, para o runner de CI continuar em CONFERIR. Golden tests em `tests/golden/test_whole_drive_and_unclassified.py`.
- **PR #3 fundido antes do fim da fase**: o João fundiu-o (21:22 UTC) antes de eu receber o pedido para o manter em rascunho. O trabalho seguinte está no PR #4, em rascunho.

### Pendentes que passam para a Fase 2 e 3

- Docs ainda por escrever: ARCHITECTURE.md, DESIGN.md (Fase 2).
- Fase 3: a regra de remoção tem de usar o `signer` real em Program Files; o Remediator revalida cada caminho contra o `safety` com os caminhos canónicos vindos de `platform/windows/paths.py`.

## Fase 2: interface (PR #6)

Estado: etapas 0 a 3 (contexto, verificação, diagnóstico, autorização) prontas; etapas 4 a 7 são marcadores até à Fase 3.

### Feito

- `docs/DESIGN.md`, tema, logótipo e ícone, modelo de plano e autorização (nada altera o sistema sem plano autorizado).
- Capturas a 100% e 150% geradas no CI Windows com a plataforma nativa (a offscreen não tem fontes no Windows e desenha quadrados). Revistas: legíveis nas duas escalas.
- Defeito encontrado na revisão das capturas a 150%: a barra lateral compacta mostrava scrollbars por cima dos números e cortava a etapa 7. Corrigido (sem scrollbars na barra, linhas mais baixas).
- Executáveis `--onedir` de janela e de consola no job de build de desenvolvimento.
- Ponte PowerShell: no máximo dois processos em simultâneo, timeouts de 120 s e 240 s (o teste de integração falhava por arranques lentos).

### Onde foi testado

| Item | Linux | CI Windows | Manual (João) |
| --- | --- | --- | --- |
| ruff, mypy (linux e win32), pyright | verde | verde | não aplicável |
| pytest (1403 passed, 53 skipped; UI com `QT_QPA_PLATFORM=offscreen`) | verde | verde (run 40423024969, antes da correção da barra lateral) | não testado |
| Capturas de ecrã | não aplicável | verde, revistas | não testado em Windows real |

## Fase 3: remoção (PR #7)

Estado: implementada; **não testada em Windows real**. Ver `docs/reviews/phase-3-audit.md`.

- `remediation/engine.py`: só aceita um `AuthorizedPlan`; revalida cada item contra o `safety` e o estado real; ordem fixa (ponto de restauro, informação para desfazer, processos, persistência, ficheiros, Defender, hosts, firewall); resultado só depois de verificação independente; desfazer por item e por sessão; apagar a quarentena só a pedido.
- Backend Windows (`platform/windows/remediator.py`, `scripts/remediate.ps1`): `winreg`, `psutil`, ficheiro hosts em Python, resto pelo PowerShell com parâmetros em JSON.
- Limpeza opcional de temporários: passa pela quarentena como tudo o resto, desmarcada por omissão.
- Etapa 4 da interface com escolha explícita quando não há ponto de restauro.
- Testes: `tests/unit/test_remediation.py` (47), `tests/ui/test_removal.py`, `tests/integration/test_removal_windows.py` (CI Windows, artefactos marcados e inofensivos, incluindo desfazer e rejeição de ação fora do plano).

## Fase 4: confirmação e depois

Estado: implementada; não testada em Windows real.

- `core/compare.py` (diferença entre verificações, base guardada em `baseline.json`), `core/defender_scan.py` (fim da análise decidido só por eventos 1000, 1001, 1002, 1005 e pelo processo; nunca por tempo), `core/after.py` (conselhos e relatório final), `remediation/cleanup.py`.
- Páginas das etapas 5 e 6; análise do Defender num processo destacado que sobrevive à janela; retoma após reinício sem criar entradas de arranque.

## Fase 5: empacotamento

Estado: pronto exceto o teste manual. Versão 0.1.0; `packaging/LEIA-ME.txt`; `packaging/make_zip.ps1`; `.github/workflows/release.yml` (só tag `vX.Y.Z`, cria **rascunho** de release, atestado de proveniência; `workflow_dispatch` é um ensaio sem publicar). Nenhuma tag, nenhuma release.

## Próximo passo

**Pronto para release, à espera do teste manual do João** (`docs/WINDOWS_TEST_PLAN.md`, capítulos 8 e 9). Depois do OK: fundir o PR #7, tag `v0.1.0`, publicar o rascunho.
