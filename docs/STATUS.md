# STATUS

Três níveis de teste, nunca confundidos:

- **Linux**: ruff, mypy (linux e win32), pyright (Windows), pytest com backend fake.
- **CI Windows**: job `windows` em windows-latest.
- **Manual (João)**: Windows real ou VM, segundo docs/WINDOWS_TEST_PLAN.md (ainda não existe).

## Fase 0: base

Estado: fase 0 mergeada (PR #1). Endurecimento e auditoria em curso no PR `chore/phase-0-hardening`, ver `docs/reviews/phase-0-audit.md`.

### Feito

- Esqueleto do repositório conforme BRIEF §7, pyproject, `uv.lock`, Python 3.12.
- `core/models`, `core/safety`, `core/redact`, `platform/base` (Inspector e Remediator como Protocol), backend fake com fixture "PC limpo", CLI `version` e `selftest`.
- Testes: models, safety (exemplos e hypothesis), redact, backend fake, CLI, política (sem shell=True, sem APIs Windows fora de platform/windows, sem Remediator em core/scanners, sem módulos de rede), codificação dos .ps1 (ASCII ou UTF-8 com BOM).
- `.gitattributes` com LF por omissão.
- CI Ubuntu e Windows, actions fixadas por SHA, permissões mínimas, Dependabot.
- LICENSE, README.md, README.pt-PT.md, SECURITY.md.

### Hardening e auditoria (branch chore/phase-0-hardening)

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
- **Assinatura inválida em binário de sistema**: a proteção de processos depende de nome mais caminho esperado, não da assinatura. Na Fase 1, um binário de sistema com assinatura inválida tem de gerar um Finding SUSPEITO a recomendar a Análise offline do Microsoft Defender, nunca uma ação de remoção.
- **`SystemContext`**: todos os campos de localização são obrigatórios. `personal_folders` tem de vir de SHGetKnownFolderPath (OneDrive e nomes localizados como "Ambiente de Trabalho"); o `safety` não os adivinha, e há um teste a provar que sem eles a pasta NÃO fica protegida.

- **Program Files (provisório)**: `is_protected_path` protege Program Files por inteiro. A regra definitiva (BRIEF §8) é por assinatura: só Microsoft ou fabricantes de antivírus. O parâmetro `signer` já existe mas é ignorado. O teste `test_unsigned_in_program_files_can_be_removed` está marcado `xfail(strict=True)` e descreve o comportamento final: um executável sem assinatura em Program Files tem de poder entrar num plano de remoção. Resolver na Fase 1, quando houver dados de assinatura do backend.
- **Segmentos ambíguos**: caminhos com segmentos só de pontos ou espaços a meio (`C:\Windows\ \x`) são tratados como protegidos (falham fechado), porque o Windows é ambíguo. Encontrado por hypothesis.
- **Nomes 8.3**: um caminho com `~N` num componente é tratado como protegido. O backend tem de resolver o nome longo antes.
- **Redact**: hex puro de 64 caracteres sem nome ao lado não é redigido (é indistinguível de um SHA-256). Documentado em SECURITY.md.
- **UNC e raízes de unidade**: sempre protegidos.
- Ainda não existem: docs/ARCHITECTURE.md, DETECTION.md, DESIGN.md, WINDOWS_TEST_PLAN.md, modelos de issue, lock com hashes verificado em CI além de `--locked`.
- `psutil` e PySide6 não estão nas dependências: entram na Fase 1 e na Fase 2.
