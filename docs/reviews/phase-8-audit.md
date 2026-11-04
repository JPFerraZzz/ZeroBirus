# Auditoria adversarial da Fase 8 (Modo Jogo: FPS Optimizer e RAM Lover)

Âmbito: `core/tweaks.py`, `core/ram.py`, as ações `SET_REGISTRY_VALUE` e `SET_POWER_PLAN` no motor (`remediation/engine.py`), no backend Windows (`remediator.py`, `scripts/remediate.ps1`), no backend de demonstração (`platform/fake/ops.py`) e `ui/page_game.py`. Método: ler como atacante (plano hostil, pasta de sessão adulterável, sistema que mente) e escrever o teste antes de dar por bom. Feita pelo mesmo autor do código, por isso **não substitui uma revisão independente**. Não testado em Windows real.

## Barreiras verificadas por teste (`tests/unit/test_tweaks.py`, `tests/ui/test_game.py`)

| Ameaça | Barreira | Teste |
| --- | --- | --- |
| Plano com uma chave de registo que não é do catálogo (por exemplo `DisableAntiSpyware` do Defender) disfarçada com o nome de uma definição permitida | `catalog_tweak_for`: o item tem de ser igual, parâmetro a parâmetro, a uma entrada do catálogo; senão `IGNORADO`, nada escrito | `test_an_item_outside_the_catalog_is_refused` |
| Plano de energia que não é o permitido | Só os GUIDs de `POWER_PLANS` | `test_an_unknown_power_plan_is_refused` |
| Registo para desfazer adulterado (outra chave ou outro valor) | O id deixa de corresponder ao conteúdo e o registo é recusado; além disso o desfazer volta a passar pelo catálogo | `test_a_tampered_undo_record_is_not_acted_on` |
| Dado guardado para repor que não é um número ou um GUID | O backend Windows e o de demonstração validam antes de escrever | `restore` em `remediator.py` e `fake/ops.py` |
| Alteração que "diz que fez" mas o Windows não aceitou | `APLICADO` só depois de reler o valor; senão `FALHOU` | `test_a_change_that_does_not_stick_is_not_reported_as_done` |
| Definição que não existe neste PC (agendamento da GPU) | A captura falha, o item não é alterado | `test_a_setting_that_does_not_exist_here_is_not_touched` |
| RAM Lover a oferecer o antivírus, um processo do Windows ou a própria ferramenta | Processos protegidos e a própria ferramenta fora; em Program Files só com a assinatura realmente verificada (assinante desconhecido falha fechado) | `test_an_antivirus_or_windows_program_is_never_offered`, `test_a_program_under_program_files_is_offered_only_with_a_checked_signer`, `test_the_tool_itself_is_never_offered` |
| PID reutilizado por outro programa entre a lista e o clique | O motor compara o caminho do processo vivo com o do plano | `test_closing_a_program_whose_pid_was_reused_is_refused` |
| Mudar o sistema sem plano gravado | O `plan.json` fica na sessão antes de qualquer alteração | `test_the_plan_is_saved_in_the_session_before_anything_changes` |
| Catálogo a tocar em segurança | Teste que procura palavras de segurança nos títulos e parâmetros | `test_catalog_has_unique_ids_and_never_touches_security` |

## Riscos residuais (não corrigidos)

1. **HKCU do utilizador errado.** As definições do Modo de Jogo são por utilizador (`HKCU`). Se o ZeroBirus for aberto como administrador com outra conta (UAC com credenciais de outro utilizador), muda as definições dessa conta, não da pessoa que joga. Passo seguinte: escrever em `HKU\<SID>` do utilizador da sessão.
2. **Fechar programas não se desfaz** e o motor não volta a perguntar pelo assinante: a barreira do antivírus em Program Files está na construção da lista, não na camada de execução. Um plano forjado a chamar `KILL_PROCESS` para um antivírus fora das pastas protegidas só é travado pela lista de nomes de `is_protected_process`.
3. **Plano de energia de alto desempenho** pode não existir (Modern Standby): nesse caso o `powercfg` falha e o item dá `FALHOU`. Testado só com o backend de demonstração.
4. **Repor** escreve o valor que estava antes. Se a pessoa mudou a definição à mão entretanto, é substituída pelo valor antigo.
5. **Lista de espera (standby) da RAM** não foi implementada: precisa de um privilégio e de uma chamada nativa que não consigo provar sem Windows real. O RAM Lover diz isso no ecrã.
6. Tudo o que é Windows (registo, `powercfg`, PowerShell) só foi coberto pelo backend de demonstração e pelo teste de integração `tests/integration/test_tweaks_windows.py`, que ainda não correu no CI.
