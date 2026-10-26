# Auditoria adversarial da Fase 0

Âmbito: `core/safety.py`, `core/redact.py`, testes de política. Princípio: na dúvida, falha fechado. Método: para cada problema, primeiro um teste que falha, depois a correção, depois o teste a passar.

Tudo foi verificado em Linux. Nada disto foi testado em Windows real: o comportamento exato do Windows com caminhos exóticos (dobra de maiúsculas, tratamento de `\\?\`, segmentos só de pontos) está modelado a partir da documentação e de conhecimento geral, e por isso as decisões foram sempre pelo lado mais protegido.

## Como foi feita a auditoria

| Ferramenta | Resultado |
| --- | --- |
| Sondas escritas à mão (`test_safety_adversarial.py`, `test_redact_adversarial.py`) | Antes das correções: 73 falhas em `safety` e 43 em `redact`. Depois: todas passam. |
| Segunda leitura adversarial do código já corrigido | Encontrou mais 4 problemas (linhas 17, 23, 24 e 25 da tabela). |
| mutmut 3.8.0 sobre `safety.py` e `redact.py` | Primeira corrida: 598 mutantes, 546 mortos, 52 sobreviventes. Corrida final: 598 mutantes, 597 mortos, 1 sobrevivente equivalente. |
| Hypothesis, perfil `deep` (5000 exemplos por propriedade) | Sem contraexemplos. |
| Sonda diferencial com oráculo independente (simulação simples do Win32), 100 000 exemplos com componentes hostis | Sem contraexemplos. Não ficou no repositório porque não encontrou nada. |
| Testes de política: violações injetadas nos ficheiros reais | Ver linhas 31 e 32. |

Mutante sobrevivente final (equivalente): `key.strip().rstrip(" .")` mutado para `rstrip("XX .XX")`. A chave já passou por `upper().lower()`, por isso nunca contém `X` maiúsculo e as duas versões comportam-se igual. Antes disso, dois sobreviventes (`rsplit` com `maxsplit` diferente) foram eliminados trocando por `rpartition`, e quatro verificações redundantes foram removidas do código.

## Problemas encontrados

Gravidade: Alta = a ferramenta podia tocar em algo do Windows, ou deixar passar um segredo, ou ser bloqueada. Média = degrada a proteção ou a utilidade. Baixa = robustez.

### safety

| # | Problema | Como foi encontrado | Gravidade | Estado |
| --- | --- | --- | --- | --- |
| 1 | `SystemContext` com valores por omissão: campos vazios significavam "nada protegido" sem aviso, e o Windows pode estar noutra unidade | Revisão do João | Alta | Corrigido. Campos obrigatórios e validados em `__post_init__` (vazio, relativo, UNC, raiz de unidade, nome 8.3, carateres inseguros dão `ValueError` com o nome do campo). |
| 2 | Proteção de processos dependia de `signed_by_microsoft`: `System` e `Registry` (sem ficheiro) ficavam desprotegidos, e um binário de sistema com assinatura inválida podia entrar num plano de morte de processos | Revisão do João | Alta | Corrigido. Proteção por nome mais caminho esperado. Assinatura inválida passa a ser Finding SUSPEITO na Fase 1. |
| 3 | Processo de sistema genuíno sem caminho (acesso negado ao ler o executável, comum em `psutil`) ficava desprotegido | Sonda de processos | Alta | Corrigido. Nome protegido sem caminho continua protegido. |
| 4 | Processo de sistema com caminho não canónico (8.3, barras `/`, espaço ou ponto final, relativo) ficava desprotegido | Sonda de processos | Alta | Corrigido. Só um caminho canónico fora do local esperado marca um impostor. |
| 5 | Nome de processo sem `.exe`, com espaços, pontos finais, em largura total, ou o próprio caminho completo no campo do nome | Sonda de processos | Média | Corrigido (`_process_key`). |
| 6 | Faltavam `Memory Compression`, `Secure System`, `System Idle Process`, `NisSrv.exe`, `sgrmbroker`, `lsaiso`; `SysWOW64` não era aceite como local esperado | Revisão contra o BRIEF §8 | Média | Corrigido. |
| 7 | Nomes de dispositivo reservados (`NUL`, `CON.txt`, `COM1`, `COM¹`, `CONIN$`) em qualquer componente: o Win32 mapeia-os para o dispositivo, não para um ficheiro | Sonda de caminhos | Média | Corrigido. Protegido. |
| 8 | NUL, carateres de controlo, curingas e `< > " \| ? *`: o Win32 trunca no NUL e os curingas expandem para vários ficheiros | Sonda de caminhos | Alta | Corrigido. Protegido. |
| 9 | `%` no caminho: uma segunda expansão de variáveis a jusante podia mudar o destino | Sonda de caminhos | Média | Corrigido. Protegido. |
| 10 | Caminhos com mais de 32767 carateres | Sonda de caminhos | Baixa | Corrigido. Protegido. |
| 11 | Unicode que o Windows ou o mapeamento ANSI "best fit" podem dobrar para ASCII: `ſ` (s longo), `ＷＩＮＤＯＷＳ`, `＼`, `．．` | Sonda de caminhos | Alta | Corrigido com NFKC e `upper().lower()`. |
| 12 | `..` tratado só por colapso; em caminhos `\\?\` o Windows trata-o como nome literal | Revisão | Média | Corrigido. São avaliadas quatro leituras (com e sem NFKC, `..` colapsado e literal) e basta uma estar protegida. |
| 13 | Outra instalação do Windows (`E:\Windows`) e ficheiros de sistema na raiz de qualquer unidade (`pagefile.sys`, `hiberfil.sys`, `bootmgr`, `Boot`, `EFI`, `Recovery`, `System Volume Information`, `$Recycle.Bin`) | Sonda de caminhos | Alta | Corrigido. |
| 14 | Hives do registo no perfil (`NTUSER.DAT`, `UsrClass.dat`, ficheiros `.LOG`) não estavam protegidas | Sonda de caminhos | Alta | Corrigido. |
| 15 | Só os perfis listados em `profile_roots` eram protegidos: `C:\Users\Bob`, `Default`, `Public`, e as raízes `AppData`, `AppData\Local`, `Roaming`, `Local\Temp`, `Downloads` ficavam desprotegidas | Sonda de caminhos | Alta | Corrigido. Qualquer filho de `users_dir` conta como perfil. Apagar a raiz de `Temp` é recusado, o conteúdo individual não. |
| 16 | `ProgramData\Microsoft\Windows Defender Advanced Threat Protection` | Sonda de caminhos | Média | Corrigido. |
| 17 | Regressão minha: ao reescrever, perfis fora de `users_dir` (por exemplo `D:\Perfis\Ana`) perderam a proteção de Documentos, Ambiente de trabalho e AppData | Segunda leitura | Média | Corrigido. Teste novo. |
| 18 | Segmentos só de pontos ou espaços a meio do caminho (`C:\Windows\ \0`) faziam o caminho sair de `C:\Windows` | Hypothesis (durante a Fase 0) | Alta | Corrigido. Protegido (ambíguo). |

### redact

| # | Problema | Como foi encontrado | Gravidade | Estado |
| --- | --- | --- | --- | --- |
| 19 | ReDoS quadrático no padrão de URLs com credenciais: 0,6 s para 30 000 letras seguidas, cresce com o quadrado (300 000 carateres dão minutos). Uma linha de comando hostil podia bloquear a ferramenta | Medição com entradas adversariais | Alta | Corrigido com âncora por lookbehind. Os testes de `redact` passaram de 280 s para 2 s. Teste de tempo linear com 200 000 carateres em 30 entradas hostis. |
| 20 | Segundo ReDoS, mais subtil: `-pa-pa-pa...` fazia o padrão das chaves curtas arrancar a cada `-` | Teste de tempo, durante a correção anterior | Média | Corrigido (lookbehind inclui `_.-`). |
| 21 | Formatos que vazavam: chaves PEM, JSON `"password":"..."`, cabeçalhos em várias linhas, `Cookie`, `bearer` solto, `/p:x`, `/pass:x`, `-pSEGREDO` colado, tokens GitHub, AWS, Google, Stripe, npm, Hugging Face, JWT, endereço Monero integrado | Sondas de formatos | Alta | Corrigido. |
| 22 | Falsos positivos que destruíam informação: pasta aleatória de 40 ou mais carateres em AppData (exatamente a evidência que importa), `svchost.exe -k netsvcs -p -s Schedule`, `Bypass`, `compass=`, prosa como "the token expired" | Sondas de falsos positivos | Média | Corrigido. Hashes de 32, 40 e 64 hex e componentes de caminho sobrevivem. |
| 23 | Segunda leitura: `{"Authorization":"Basic ..."}` e `Cookie` em JSON vazavam (o padrão não aceitava valor entre aspas) | Segunda leitura | Alta | Corrigido. |
| 24 | `-Password (ConvertTo-SecureString "texto" -AsPlainText -Force)`: o texto em claro ficava | Segunda leitura | Alta | Corrigido. |
| 25 | `schtasks /RP segredo` | Segunda leitura | Média | Corrigido. |
| 26 | Texto em claro de um valor entre aspas com aspas escapadas e aspas não fechadas | Sondas de formatos | Média | Corrigido. |

### Testes de política

| # | Problema | Como foi encontrado | Gravidade | Estado |
| --- | --- | --- | --- | --- |
| 27 | `subprocess.run(..., **kw)` com `shell` dentro de um dicionário passava o teste | Violação injetada no código real | Alta | Corrigido. |
| 28 | `os.system`, `os.popen`, `subprocess.getoutput`, `eval` e `exec` não eram detetados | Revisão | Média | Corrigido. |
| 29 | `importlib.import_module("winreg")` e `__import__("socket")` não eram detetados | Violação injetada | Média | Corrigido (constantes de texto também contam). |
| 30 | `import zerobirus.platform.windows` fora do backend só era apanhado por um teste dinâmico | Revisão | Média | Corrigido (estático). |
| 31 | Lista de módulos de rede incompleta (`ssl`, `socketserver`, `urllib3`, `aiohttp`, `paramiko`...) | Revisão | Baixa | Corrigido. |
| 32 | Os detetores nunca tinham sido provados contra violações | Pedido do João | Média | Corrigido. Os detetores são funções puras e mais de 40 casos sintéticos de violação correm em cada CI. |

Prova com violações injetadas nos ficheiros reais (depois de reforçar): `shell=True` falha 1 teste, `shell` por `**kwargs` falha 1, `os.system` falha 1, `import winreg` em `core` falha 2, `importlib.import_module("winreg")` falha 2, `c.windll` falha 2, `Remediator` em `core` falha 2, `import zerobirus.platform.windows` a partir do `cli` falha 2, `import socket` falha 1. Os ficheiros foram restaurados a seguir.

## Riscos aceites e limites

| Limite | Porquê é aceite |
| --- | --- |
| Program Files protegido por inteiro | Provisório. A regra final é por assinatura (BRIEF §8). Teste `xfail(strict=True)` descreve o comportamento final. |
| `C:\Windows\Temp` protegido por inteiro | Decisão pendente do João. O malware cai muitas vezes ali. |
| `System` e `Registry` protegidos pelo nome só quando o caminho vem vazio. Com um caminho real são tratados como impostor (BRIEF §8), não protegidos | Divergência pequena em relação à instrução A3, que dizia "protegidos pelo nome". Fiz assim porque o BRIEF diz que o mesmo nome fora do caminho esperado não é protegido, e um `System` com ficheiro em disco é anómalo. Decisão do João se preferir proteção incondicional. |
| `C:\Windows.old` e `C:\WindowsEvil` não são protegidos | Intencional: não são o diretório do Windows. |
| Qualquer caminho UNC é protegido | A ferramenta nunca remove em partilhas de rede. |
| Nome com `~N` (por exemplo `a~1.txt`) é tratado como 8.3 e fica protegido | O backend entrega o nome longo canónico, por isso um nome legítimo assim só falha por defeito. |
| Dobra de maiúsculas e best-fit são aproximados | A leitura aproximada só pode proteger mais, nunca menos. Não confirmado em Windows real. |
| `redact`: hex de 64 caracteres sem nome ao lado não é redigido | Indistinguível de um SHA-256 que o relatório tem de mostrar. Documentado em SECURITY.md. |
| `redact`: `-pXXX` colado e `-u valor` redigem sempre | Redigir a mais é aceitável (por exemplo `-pool` fica `-[oculto]`). |
| `redact`: segredos posicionais sem marcador (`net use \\srv palavra-passe`) e palavras-passe com espaços sem aspas | Não há como distinguir de texto normal. |
| `redact`: sequência de 40 ou mais letras fora de um caminho é redigida | Fail closed. Uma sequência com `/` e sem dígitos nem `+` é tratada como nome de caminho e mantida. |

## O que `safety` não pode garantir sozinho (contrato com o backend)

Registado também em `docs/STATUS.md`.

- Caminhos canónicos obtidos com `GetFinalPathNameByHandle`. Sem isso, as garantias de `safety` não valem.
- Verificar a troca entre análise e remoção (TOCTOU), hard links e junções no momento de mover. É um problema do Remediator.
- `own_pids` tem de incluir o processo, o pai e os filhos do ZeroBirus.
- Antivírus de terceiros: não há lista por nome. Tem de ser decidido por assinatura na Fase 1 e 3.
- `personal_folders` vem de `SHGetKnownFolderPath`. O `safety` não adivinha nomes localizados.

## Não feito

- Sem confirmação em Windows real de nenhuma das hipóteses sobre o comportamento do Win32.
- Sem fuzzing de longa duração. O perfil `deep` do Hypothesis e a sonda de oráculo correram uma vez, localmente.
- O mutmut não corre no CI (dependência só local, grupo `mutation`).

## Resultados no Windows real (CI windows-latest, 2026-10-26)

Teste diferencial só de leitura (`tests/unit/test_windows_paths.py`) sobre `cmd.exe`, `kernel32.dll`, `drivers\etc\hosts`, `System32\config` e `explorer.exe`. Para cada grafia que o Windows abre e resolve para dentro de `SystemRoot` com `GetFinalPathNameByHandleW`, `is_protected_path` devolveu True para a grafia original. Nenhuma hipótese do audit foi contradita e não foi preciso corrigir o `safety`.

- Resolvem: barras normais, `\\?\`, `\\.\`, maiúsculas, minúsculas, ponto e espaço finais, `..`, `.`, barra dupla, nome 8.3, `::$DATA`.
- Não resolvem (erro 2, 3 ou 5): `ſ`, largura total (`ＷＩＮＤＯＷＳ`), `:$DATA` explícito e `config::$DATA`. O `CreateFileW` não faz essa dobra, por isso a dobra NFKC do `safety` é só margem de segurança contra camadas ANSI a jusante, não um comportamento observado do Windows.
- psutil, dados reais: System (PID 4) vem com `path=None`. **Registry vem com `path='Registry'`**, que não é um caminho. Continua protegido porque um nome protegido com caminho não canónico falha fechado. Pinado em `tests/unit/test_safety_psutil_recorded.py`. Memory Compression não existe no runner (skip).
