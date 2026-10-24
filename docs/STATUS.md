# STATUS

Três níveis de teste, nunca confundidos:

- **Linux**: ruff, mypy (linux e win32), pyright (Windows), pytest com backend fake.
- **CI Windows**: job `windows` em windows-latest.
- **Manual (João)**: Windows real ou VM, segundo docs/WINDOWS_TEST_PLAN.md (ainda não existe).

## Fase 0: base

Estado: CI verde nos dois sistemas (PR #1). Aguarda revisão e OK do João para merge.

### Feito

- Esqueleto do repositório conforme BRIEF §7, pyproject, `uv.lock`, Python 3.12.
- `core/models`, `core/safety`, `core/redact`, `platform/base` (Inspector e Remediator como Protocol), backend fake com fixture "PC limpo", CLI `version` e `selftest`.
- Testes: models, safety (exemplos e hypothesis), redact, backend fake, CLI, política (sem shell=True, sem APIs Windows fora de platform/windows, sem Remediator em core/scanners, sem módulos de rede), codificação dos .ps1 (ASCII ou UTF-8 com BOM).
- `.gitattributes` com LF por omissão.
- CI Ubuntu e Windows, actions fixadas por SHA, permissões mínimas, Dependabot.
- LICENSE, README.md, README.pt-PT.md, SECURITY.md.

### Onde foi testado

| Item | Linux | CI Windows (PR #1) | Manual (João) |
| --- | --- | --- | --- |
| ruff, mypy (linux e win32), pyright | verde | mypy verde (ruff e pyright só correm no Ubuntu) | não aplicável |
| pytest (unit, política, encoding) | verde (145 passed, 4 skipped, 1 xfailed) | verde (148 passed, 1 skipped, 1 xfailed) | não testado |
| testes marcados `windows` (4) | skipped por desenho | verde (4 passed) | não testado |
| `zerobirus version` e `selftest` | verde | verde | não testado |

O skip no Windows é `test_windows_backend_not_imported_off_windows`, que só faz sentido fora do Windows.

Nada disto foi testado em Windows real (só no runner windows-latest). Todo o `core/safety` trabalha só sobre strings, por isso a correspondência com o comportamento real do Windows (por exemplo, como o Windows trata `C:\Windows\ \x`) só se confirma no CI Windows e no teste manual.

### Pendentes e decisões a registar

- **Program Files (provisório)**: `is_protected_path` protege Program Files por inteiro. A regra definitiva (BRIEF §8) é por assinatura: só Microsoft ou fabricantes de antivírus. O parâmetro `signer` já existe mas é ignorado. O teste `test_unsigned_in_program_files_can_be_removed` está marcado `xfail(strict=True)` e descreve o comportamento final: um executável sem assinatura em Program Files tem de poder entrar num plano de remoção. Resolver na Fase 1, quando houver dados de assinatura do backend.
- **Segmentos ambíguos**: caminhos com segmentos só de pontos ou espaços a meio (`C:\Windows\ \x`) são tratados como protegidos (falham fechado), porque o Windows é ambíguo. Encontrado por hypothesis.
- **Nomes 8.3**: um caminho com `~N` num componente é tratado como protegido. O backend tem de resolver o nome longo antes.
- **Redact**: hex puro de 64 caracteres sem nome ao lado não é redigido (é indistinguível de um SHA-256). Documentado em SECURITY.md.
- **UNC e raízes de unidade**: sempre protegidos.
- Ainda não existem: docs/ARCHITECTURE.md, DETECTION.md, DESIGN.md, WINDOWS_TEST_PLAN.md, modelos de issue, lock com hashes verificado em CI além de `--locked`.
- `psutil` e PySide6 não estão nas dependências: entram na Fase 1 e na Fase 2.
