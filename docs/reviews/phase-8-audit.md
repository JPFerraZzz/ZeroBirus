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

## Adenda da Fase 9 (MegaTweaker)

O MegaTweaker usa o mesmo motor e o mesmo catálogo: 16 definições novas em 4 categorias (Privacidade e recomendações, Aspeto e animações, Jogos e rede, Sistema e arranque), todas um único valor numérico de registo. Níveis: seguro, moderado, agressivo. As agressivas (efeitos visuais de melhor desempenho e reserva de processador para segundo plano) vêm desmarcadas, num grupo próprio com aviso, e exigem uma caixa de confirmação para aplicar.

- Testes novos: o catálogo completo aplica-se e desfaz-se; um item com valor alterado é recusado; o catálogo não contém palavras de segurança (Defender, firewall, Windows Update, SmartScreen, Security Center, pasta System32); cada categoria existe; `HKLM` implica administrador.
- Os nomes e valores de registo vêm do meu conhecimento do Windows 10 e 11, **não** de uma verificação numa máquina real. Algumas definições (telemetria, arranque rápido, otimizações de ecrã inteiro) podem não ter efeito nalgumas edições ou versões; nesse caso a verificação relê o valor e dá `APLICADO` por o valor estar lá, o que não prova o efeito. O teste manual do João é a prova.
- `AllowTelemetry` fica numa chave de política: se o PC estiver gerido por uma organização, a política dela pode mandar mais do que isto.
- O valor `0xFFFFFFFF` (`NetworkThrottlingIndex`) passa pelo mesmo caminho dos outros, mas é o único acima de 2 mil milhões; coberto só pelo backend de demonstração.

## Adenda da Fase 10 (BigDiag e AllUp)

**BigDiag** é só de leitura: `bigdiag.ps1` passa pelo teste estático que proíbe qualquer verbo que altere estado, e não recolhe nomes de pessoas nem do PC. Cada parte lê-se à parte; o que falha aparece como "não foi possível ler", nunca como "tudo bem" (testado). O ficheiro exportado passa pelo redator inteiro (testado com um caminho pessoal e uma palavra-passe na linha de comando). Riscos: o ficheiro de texto do MRT (`mrt.log`) é lido como dados e só procura duas frases; a temperatura do processador depende de o fabricante expor o sensor ACPI e muitas vezes não expõe (o relatório diz isso).

**AllUp** instala software, o que o ZeroBirus não consegue desfazer. Barreiras:

| Ameaça | Barreira | Teste |
| --- | --- | --- |
| Texto do winget que parece um pacote mas é uma opção ou um comando (`--force`, `a;b`, `$(x)`) | O id só passa se casar com `^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`; linhas que não casam são deixadas de fora | `test_parse_ignores_anything_that_is_not_a_table`, `test_package_ids_that_could_be_options_or_commands_are_not_ids` |
| Atualizar algo que a pessoa não viu | O plano só aceita ids que estavam na lista; um id desconhecido é erro | `test_the_plan_only_takes_listed_ids` |
| Plano alterado depois de autorizado | A soma de controlo do plano é verificada antes de correr; nada corre se não coincidir | `test_a_plan_altered_after_authorising_is_refused_and_nothing_runs` |
| O winget diz que correu bem mas não ficou | "Confirmada" só se uma nova listagem já não mostrar o pacote | `test_a_success_that_does_not_stick_is_not_claimed` |
| Um pacote falha | Os seguintes continuam; o falhado diz porquê | `test_a_failing_package_does_not_stop_the_next_one` |
| Plano só em memória | `allup-plan.json` fica na sessão antes de instalar | `test_allup_updates_the_ticked_ones_writes_the_plan_first_and_confirms_each` |

Riscos residuais: (1) o `winget` é encontrado pela pasta `WindowsApps` do utilizador (via `SHGetKnownFolderPath`), não por uma pasta sob `%SystemRoot%` como as outras ferramentas, porque é um alias de aplicação por utilizador; (2) o analisador da tabela lê por posição das palavras a partir da direita e foi escrito para saídas em inglês e português, não testado com a saída real do winget; (3) o winget pode atualizar um antivírus de terceiros: não filtramos, e uma atualização não é desativar; (4) pacotes que pedem reinício ou administrador falham e ficam como "não confirmada"; (5) as atualizações do próprio Windows (Windows Update) não estão no AllUp.

## Adenda da Fase 11 (FirstSetup e AllDrivers)

**FirstSetup** gera `ZeroBirus-FirstSetup.cmd` no Ambiente de trabalho, em texto ASCII com CRLF, com a marca "ZeroBirus - by Ferraz". O ZeroBirus não descarrega nada: o script chama o `winget` (D-016) e, depois de cada instalação, volta a perguntar ao winget se o pacote está na lista de instalados; só então escreve "CONFIRMADA". Barreiras:

| Ameaça | Barreira | Teste |
| --- | --- | --- |
| Um id ou um nome que o `cmd.exe` interprete (`&`, `|`, `%`, `^`, `"`, parênteses) | O id tem de estar no catálogo e casar com o padrão estrito de ids; os nomes só têm caracteres seguros e os parênteses são retirados do que o script escreve | `test_the_script_contains_nothing_cmd_would_give_a_meaning_to`, `test_the_script_refuses_ids_outside_the_catalog` |
| Acentos que o `cmd` estragaria por causa da página de códigos | O script é só ASCII (falha se escapar um carácter) | `test_the_script_is_ascii_crlf_branded_and_installs_then_checks_each_app` |
| Substituir um ficheiro que a pessoa guardou | Nunca sobrescreve: acrescenta `-2`, `-3` | `test_firstsetup_writes_the_installer_to_the_desktop_and_never_overwrites` |

Riscos residuais: (1) o script chama `%LOCALAPPDATA%\Microsoft\WindowsApps\winget.exe` a partir do ambiente do utilizador quando for aberto, não por um caminho calculado pelo ZeroBirus; (2) 35 dos ids do catálogo não foram verificados no repositório (limite de pedidos do GitHub) e 3 não existem e foram retirados; `tools/check_winget_ids.py` verifica o resto; (3) a categoria Security tem um só antivírus (Malwarebytes), porque não confirmei os ids dos outros; (4) o script não é assinado: o SmartScreen pode avisar na primeira vez; (5) "CONFIRMADA" quer dizer que o winget a lista como instalada, não que arranca.

**AllDrivers** é só leitura mais abrir páginas. `drivers.ps1` lê os drivers (Win32_PnPSignedDriver) e pergunta ao Windows Update o que tem pendente (a pesquisa não instala nada). Só abre os 4 endereços de `core.drivers.LINKS`; qualquer outro é recusado e o ecrã diz que não foi possível (testado). Desvio do ROADMAP: «instalar por aí» é abrir as Atualizações opcionais do Windows, não instalar por COM, para o ZeroBirus não instalar drivers (risco de ecrã preto). Riscos: a pesquisa do Windows Update precisa de rede e demora; a data do driver não é a da instalação.
