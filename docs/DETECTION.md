# DETECTION

O que cada verificação lê, porquê, falsos positivos conhecidos e limites. Estado: Fase 1, só leitura. Nada aqui altera o sistema.

Duas regras valem para tudo:

- A pontuação usa sempre as cadeias originais vindas da máquina (por exemplo a linha de comando completa). O `redact` e a remoção de dados pessoais só se aplicam à saída (relatório, registos, interface). Um teste de política impede os módulos de pontuação de importar o `redact`.
- Uma verificação que não correu, ou que correu só em parte, é NAO_VERIFICADO com o motivo. Nunca conta como OK.

## Níveis e pontuação

| Nível | Significado |
| --- | --- |
| OK | Confirmado como legítimo por evidência positiva (assinatura Microsoft válida no caminho esperado, ou fabricante conhecido assinado no caminho esperado). O nome sozinho nunca basta. |
| CONFERIR | Ambíguo. Pontuação de 30 ou mais. |
| SUSPEITO | Prova forte (um sinal forte) ou pontuação de 100 ou mais. |
| NAO_VERIFICADO | A verificação não correu ou ficou incompleta. |

A pontuação é aditiva e explicável: cada Finding guarda a lista de sinais com texto em pt-PT. Um sinal fraco sozinho nunca dá SUSPEITO (há um teste que prova isto para cada sinal do ficheiro). Uma assinatura válida baixa a pontuação mas não anula um sinal forte, porque existem certificados roubados. Pesos e limiares estão em `src/zerobirus/core/rules/scoring.json` e `tests/unit/test_scoring.py` fixa o comportamento.

### Sinais

A tabela é gerada a partir de `scoring.json`; `tests/unit/test_detection_doc.py` falha se um sinal faltar aqui.

| Código | Peso | Forte | Ameaça | Texto mostrado |
| --- | --- | --- | --- | --- |
| `cmdline_miner_marker` | 100 | sim | minerador | A linha de comando tem marcas típicas de mineração de criptomoeda. |
| `cmdline_pool_domain` | 100 | sim | minerador | A linha de comando liga a um domínio conhecido de pool de mineração. |
| `cmdline_miner_weak` | 30 | não | minerador | A linha de comando tem várias opções que também aparecem em mineradores. |
| `miner_process_name` | 70 | não | minerador | O nome do programa é o de um minerador conhecido. |
| `high_cpu` | 25 | não | minerador | Usa muito processador de forma continuada. |
| `writable_location` | 20 | não |  | Corre a partir de uma pasta onde o utilizador pode escrever (AppData, Temp, ProgramData ou Public). |
| `random_folder` | 25 | não |  | A pasta ou o ficheiro tem um nome de aspeto aleatório. |
| `unsigned` | 15 | não |  | Não tem assinatura digital. |
| `invalid_signature` | 40 | não |  | A assinatura digital é inválida. |
| `valid_signature` | -30 | não |  | Tem assinatura digital válida (baixa a pontuação, não anula outras provas). |
| `system_binary_bad_signature` | 100 | sim | trojan | Um ficheiro do sistema tem assinatura inválida ou foi alterado. |
| `system_name_wrong_location` | 100 | sim | trojan | Tem o nome de um processo do Windows mas está fora da pasta onde esse processo vive. |
| `mining_port_writable` | 100 | sim | minerador | Liga a uma porta usada por pools de mineração a partir de uma pasta gravável pelo utilizador. |
| `mining_port_other` | 30 | não | minerador | Liga a uma porta usada por pools de mineração. |
| `persist_writable` | 35 | não |  | Arranca com o Windows a partir de uma pasta gravável pelo utilizador. |
| `persist_unsigned_random_writable` | 100 | sim | trojan | Arranca com o Windows um programa sem assinatura, com nome aleatório, numa pasta gravável pelo utilizador. |
| `winlogon_changed` | 70 | não | trojan | O arranque da sessão (Winlogon) foi alterado em relação ao normal. |
| `appinit_dll` | 50 | não | trojan | Há DLLs carregadas em todos os programas (AppInit_DLLs). |
| `ifeo_debugger` | 40 | não | trojan | Um programa está redirecionado para outro (Image File Execution Options). |
| `task_outside_microsoft` | 10 | não |  | Tarefa agendada fora da pasta Microsoft. |
| `task_from_writable` | 60 | não |  | A tarefa executa um programa de uma pasta gravável pelo utilizador. |
| `task_disguised_microsoft` | 70 | não | trojan | Está numa pasta com nome da Microsoft mas executa um programa de uma pasta gravável pelo utilizador. |
| `task_frequent` | 10 | não |  | Repete-se com muita frequência. |
| `service_non_microsoft` | 15 | não |  | Serviço que não é da Microsoft. |
| `service_from_writable` | 60 | não |  | O serviço executa um programa de uma pasta gravável pelo utilizador. |
| `shell_command` | 25 | não |  | Executa através de uma consola de comandos ou de um interpretador de scripts. |
| `file_in_writable` | 15 | não |  | Executável numa pasta gravável pelo utilizador. |
| `referenced_by_persistence` | 40 | não | trojan | Algo no arranque do Windows aponta para este ficheiro. |
| `defender_exclusion_covers` | 10 | não |  | O Microsoft Defender tem uma exclusão que cobre este ficheiro. |
| `defender_exclusion_and_persistence` | 100 | sim | trojan | O Defender foi instruído a ignorar uma pasta com um executável que também arranca com o Windows. |
| `running_from_file` | 20 | não |  | Está a correr neste momento. |
| `crack_folder` | 20 | não |  | Está numa pasta com nome de crack, keygen ou ativador. |
| `defender_realtime_off` | 50 | não |  | A proteção em tempo real do Defender está desligada. |
| `defender_tamper_off` | 30 | não |  | A proteção contra adulteração do Defender está desligada. |
| `defender_signatures_old` | 20 | não |  | As assinaturas do Defender estão desatualizadas. |
| `defender_signatures_very_old` | 40 | não |  | As assinaturas do Defender estão muito desatualizadas. |
| `defender_threat_history` | 40 | não |  | O Defender tem ameaças no histórico. |
| `defender_exclusion_path_writable` | 50 | não |  | Exclusão do Defender sobre uma pasta gravável pelo utilizador. |
| `defender_exclusion_whole_drive` | 50 | não |  | O Defender foi instruído a não analisar uma unidade inteira. |
| `defender_exclusion_path` | 30 | não |  | Exclusão de pasta no Defender. |
| `defender_exclusion_extension` | 40 | não |  | Exclusão de extensão de executáveis no Defender. |
| `defender_exclusion_process` | 30 | não |  | Exclusão de processo no Defender. |
| `defender_exclusion_ip` | 30 | não |  | Exclusão de endereço IP no Defender. |
| `hosts_security_domain` | 100 | sim | trojan | O ficheiro hosts redireciona um domínio de segurança ou de atualizações. |
| `hosts_other` | 35 | não |  | Linha no ficheiro hosts que não é das predefinidas. |
| `wmi_command_unknown` | 100 | sim | trojan | Assinatura WMI permanente que executa comandos e não é de um fabricante conhecido. |
| `wmi_other` | 40 | não |  | Assinatura WMI permanente. |

### Tipo de ameaça e certeza

Cada sinal pode apontar para um tipo de ameaça (minerador, trojan ou porta dos fundos). O diagnóstico só nomeia um tipo quando há pelo menos um sinal forte ou três fracos. Certeza alta: dois ou mais achados com sinais fortes desse tipo. Média: um achado forte, ou três fracos. Não há certeza baixa: com menos do que isto o diagnóstico não afirma nada. Ladrão de palavras-passe e publicidade ainda não têm sinais próprios (fica para depois da Fase 1).

### Por onde pode ter entrado

Só se afirma quando há prova: uma pasta com nome de crack, keygen, ativador ou kmspico, e, se as datas dos ficheiros permitem, criada até 3 dias de diferença do ficheiro suspeito. Caso contrário o relatório diz "Não dá para saber só com isto."

## As nove verificações

### 1. Processos em execução (`processes`)

Lê: `psutil` (nome, caminho do executável, linha de comando, utilizador, processo pai) e CPU numa janela de 3 leituras (média da máquina inteira). Assinatura Authenticode só dos candidatos: os 15 que mais CPU usam, os de pastas graváveis, os com nome de processo do Windows e os de programas conhecidos.

Porquê: um minerador é o que mais CPU usa e corre de pastas onde o utilizador escreve.

Regras: processos protegidos (`core/safety`) nunca são alvo. Um nome de processo do Windows fora da sua pasta (svchost em AppData) é forte. Um binário do sistema no sítio certo mas com assinatura inválida ou em falta é SUSPEITO e recomenda a Análise offline do Microsoft Defender, nunca uma remoção. System, Registry e Memory Compression não têm ficheiro: o psutil devolve caminho vazio (System) ou o texto `Registry` (Registry), tratado como "sem imagem".

Falsos positivos conhecidos e tratados: Discord, Spotify, Steam e OneDrive a correr de AppData (programa conhecido, assinatura válida do fabricante e pasta esperada), MsMpEng a usar CPU, "Processo Ocioso do Sistema" a 90 por cento. Aparecem em "Coisas normais que assustam", agrupados.

Limites: a linha de comando é reconstruída a partir da lista de argumentos do psutil, por isso espaços e aspas podem diferir do original. Um processo que acaba enquanto é lido é ignorado.

### 2. Arranque com o Windows (`startup`)

Lê: `winreg` para Run, RunOnce e Policies\Explorer\Run (HKLM e todos os utilizadores com sessão em HKEY_USERS, vistas de 32 e 64 bits), Winlogon (Shell e Userinit), AppInit_DLLs, Image File Execution Options com Debugger e as pastas de Arranque (comum e de cada perfil). Os atalhos são resolvidos com o PowerShell (WScript.Shell, só leitura). Variáveis como `%APPDATA%` são expandidas com a pasta do perfil a que pertencem.

Regras: Shell diferente de `explorer.exe` ou Userinit diferente do normal é Winlogon alterado. AppInit_DLLs não vazio e IFEO com Debugger aparecem como sinais. Persistência sem assinatura, com nome aleatório e numa pasta gravável é forte.

Limites: o registo de utilizadores sem sessão não é lido (não se monta nenhum hive, porque isso alteraria o registo). Fica como lacuna com o nome do perfil, por isso a verificação aparece como NAO_VERIFICADO em PCs com vários perfis. As pastas de Arranque desses perfis são lidas. Não cobre ainda Active Setup, BITS, extensões do browser nem proxies (v1.1).

### 3. Tarefas agendadas (`tasks`)

Lê: PowerShell `Get-ScheduledTask` (pasta, nome, estado, ações, tipos de gatilho, intervalo de repetição). Todas são analisadas, incluindo as de \Microsoft, porque o malware usa pastas com nomes da Microsoft.

Regras: uma tarefa a executar de AppData, Temp, ProgramData ou Public é sinal, esteja onde estiver; dentro de \Microsoft pesa mais (disfarce). Repetição de 5 minutos ou menos é sinal fraco.

Limites: sem administrador algumas tarefas não são legíveis e a verificação fica NAO_VERIFICADO. Tarefas com ação COM (sem executável) não são analisadas.

### 4. Serviços (`services`)

Lê: `winreg` em HKLM\SYSTEM\CurrentControlSet\Services (serviços Win32, não controladores), com a assinatura do binário.

Regras: é da Microsoft se a assinatura é válida e Microsoft e o binário está em `%SystemRoot%` ou Program Files, nunca pelo nome. Os outros são "não Microsoft" (sinal fraco); sem assinatura são CONFERIR. svchost fora de System32 é forte.

Falsos positivos conhecidos: serviços de programas de desenvolvimento sem assinatura (Docker, PostgreSQL, MongoDB, Apache em runners de CI) aparecem como CONFERIR.

### 5. Programas em pastas graváveis (`files`)

Lê: pesquisa dirigida de executáveis e scripts (.exe, .dll, .scr, .bat, .cmd, .ps1, .vbs, .vbe, .js, .jse, .jar, .hta) em AppData\Roaming, AppData\Local\Temp, Downloads, Public, Windows\Temp, AppData\Local e ProgramData. Profundidade máxima 4, 60 000 entradas, 25 segundos, repartidos por pasta (cada pasta recebe uma parte justa do que resta, na ordem acima). Não segue junções nem links. Não varre o disco todo.

Regras: sinais fracos por local, nome aleatório, pasta de crack, e cruzamento com o que arranca com o Windows, o que está a correr e as exclusões do Defender. Exclusão do Defender mais persistência numa pasta gravável é forte. O SHA-256 é calculado só para ficheiros SUSPEITO.

Falsos positivos conhecidos e tratados: pastas `{GUID}` de ProgramData\Package Cache (caches de instaladores) não contam como nome aleatório; exclusões do Defender sobre unidades inteiras não contam contra cada ficheiro; a pasta da plataforma do Defender não é "gravável"; `.msi` não é candidato.

Limites: a pesquisa para ao atingir o tempo ou as entradas e diz qual pasta ficou por ver (NAO_VERIFICADO parcial). Pastas sem acesso contam-se e declaram-se.

### 6. Ligações de rede (`network`)

Lê: `psutil.net_connections` (ligações ativas ou a abrir, com o processo). Não resolve DNS e não faz nenhum pedido de rede.

Portas de mineração: 3333, 3334, 4444, 5555, 7777, 14433, 14444, 45700. Uma ligação a estas portas, para um endereço público, de um programa numa pasta gravável, é forte; de outro programa é só CONFERIR. Endereços locais e privados e as portas 80 e 443 são ignorados.

Limite documentado: mineradores também usam as portas 80 e 443 e pools com portas diferentes, por isso a rede sozinha não chega. Nesse caso a deteção depende da persistência e das linhas de comando. Sem administrador a lista de ligações pode ser incompleta (NAO_VERIFICADO).

### 7. Microsoft Defender (`defender`)

Lê: PowerShell `Get-MpComputerStatus`, `Get-MpPreference` e `Get-MpThreat`: proteção em tempo real, proteção contra adulteração, modo (passivo quando há outro antivírus), idade das assinaturas, histórico de ameaças e exclusões de caminho, extensão, processo e IP.

Regras: em modo passivo, "tempo real desligado" não é sinal. Sem administrador as exclusões e o histórico não são legíveis: NAO_VERIFICADO, nunca "sem exclusões". Valores vazios do PowerShell não são exclusões. Uma exclusão sobre uma unidade inteira tem sinal próprio.

Limites: se o Defender está desativado ou desinstalado, o estado não é lido (NAO_VERIFICADO com o motivo). Este projeto nunca altera o Defender nem outro antivírus. Os valores de `AMRunningMode` são nomes de enumeração do Windows, não texto traduzido.

### 8. Ficheiro hosts (`hosts`)

Lê: `%SystemRoot%\System32\drivers\etc\hosts`. Ignora comentários, linhas em branco, as predefinidas e as linhas com a marca `# ZeroBirus`.

Regras: redirecionar domínio de segurança ou de atualizações (Microsoft, fabricantes de antivírus, VirusTotal) é forte; qualquer outra linha é CONFERIR.

### 9. Assinaturas WMI (`wmi_bindings`)

Lê: PowerShell `Get-CimInstance` em `root\subscription` (ligações filtro-consumidor e o que o consumidor executa).

Regras: o consumidor predefinido do Windows (SCM Event Log) é ignorado. Um consumidor que executa comandos ou scripts e não é de um fabricante conhecido (Microsoft ou antivírus, com assinatura válida) é forte.

Limite: precisa de administrador; sem ele a verificação fica NAO_VERIFICADO.

## Assinaturas (Authenticode)

`Get-AuthenticodeSignature`, em lote e só para candidatos, nunca para o disco inteiro, com cache por caminho dentro de uma execução. O PowerShell filho recebe um `PSModulePath` fixo: um `PSModulePath` herdado (o PowerShell 7 define um) impedia o módulo de segurança de carregar e todas as assinaturas vinham desconhecidas. Quem assinou vem do campo `O=` do certificado (Microsoft Corporation, fabricantes de antivírus da lista). Assinatura desconhecida (o PowerShell não conseguiu verificar) nunca é tratada como "sem assinatura": não gera sinal e fica declarada como lacuna.

## Indicadores de mineração

Ficheiro: `src/zerobirus/core/rules/miners.json`.

- Nomes de programas: xmrig, xmr-stak, xmrig-cuda, xmrig-notls, nbminer, t-rex, trex, phoenixminer e outros.
- Marcas fortes na linha de comando: `stratum+tcp://`, `stratum+ssl://`, `stratum+tls://`, `stratum+udp://`, `stratum2+tcp://`, `--donate-level`, `--donate-over-proxy`, `randomx`, `cryptonight`, `--nicehash`.
- Marcas fracas (precisam de 2 ou mais): `--algo`, `--coin`, `--threads`, `--cpu-priority`, `--rig-id`, `--tls`, `--keepalive`, `--url=`, `--user=`, `--pass=`, `--max-cpu-usage`, `--background`.
- Domínios de pools: nanopool.org, supportxmr.com, minexmr.com, moneroocean.stream, 2miners.com, f2pool.com, ethermine.org, hashvault.pro, herominers.com, unmineable.com, nicehash.com, c3pool.com, xmrpool.eu, monerohash.com, miningpoolhub.com.

**Fontes: por confirmar.** Estas listas vêm de conhecimento geral sobre mineradores de código aberto e dos nomes de pools públicos conhecidos. Nesta sessão não foi possível confirmar cada entrada numa fonte online, por isso cada uma tem de ser verificada e referenciada (documentação de cada pool ou do minerador) antes da primeira release. As marcas fracas (`--threads`, `--tls`, `--background`) existem também em programas legítimos, razão pela qual só contam em conjunto.

## O que não é detetado (Fase 1)

Rootkits, malware só em memória e infeções do sector de arranque (usar a Análise offline do Microsoft Defender); extensões do browser, proxies, Winsock, BITS e Active Setup (v1.1); ladrões de palavras-passe e publicidade (sem sinais próprios ainda); mineradores sem persistência, sem marca na linha de comando e sem portas habituais.
