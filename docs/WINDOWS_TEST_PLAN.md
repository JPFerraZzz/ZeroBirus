# Plano de teste em Windows real (versão da Fase 1: só leitura)

Para o João, numa máquina Windows real ou numa VM. Esta versão cobre só a verificação de leitura da Fase 1. O plano completo (remoção, desfazer, executável) é escrito na Fase 5.

Este teste manual é obrigatório antes de qualquer código da Fase 3 (remoção).

Estado do que está provado e do que não está: o CI Windows (windows-latest) já corre a verificação inteira e os artefactos inofensivos (ver `docs/STATUS.md`). Nada foi testado em Windows real: um runner de CI é uma máquina limpa, sem Discord, sem jogos, sem vários perfis, sem outro antivírus e sem malware. É exatamente isso que este teste vem acrescentar.

## O que a Fase 1 faz e não faz

- Só lê. Não remove, não move, não termina processos, não altera o registo, o Defender, o hosts nem tarefas.
- Escreve um único ficheiro: o relatório que lhe pedires com `--out`.
- Efeito secundário do Windows, não nosso: o Windows PowerShell pode deixar na pasta Temp um ficheiro curto `__PSScriptPolicyTest_*.ps1`, que ele próprio cria ao arrancar. A verificação ignora-o.
- Ainda não há executável (Fase 5). A verificação corre a partir do código-fonte com `uv`.

## 0. Executável de desenvolvimento (artefacto do CI)

Cada execução do CI em `phase-*` e em PRs constrói, no job "Windows dev build", uma pasta `--onedir` com `ZeroBirus.exe` (versão de consola da CLI), manifesto de administrador (`--uac-admin`), recursos de versão com fabricante "Ferraz" e uma soma SHA-256. O artefacto chama-se `zerobirus-dev-win64` e traz `ZeroBirus-dev-win64.zip`, `SHA256SUMS.txt` e os relatórios `demo.json` (fixture sintética) e `real.json` (a verificação real do runner). Para o descarregar: separador Actions do GitHub, a execução, secção Artifacts; ou `gh run download <id> -n zerobirus-dev-win64`. Não está assinado (só o build de release será assinado, e ainda sem assinatura de código).

Para usar o ZIP em vez do código-fonte: compara o SHA-256 (`Get-FileHash ZeroBirus-dev-win64.zip` contra `SHA256SUMS.txt`), extrai tudo para uma pasta e corre `.\ZeroBirus\ZeroBirus.exe scan --json --out relatorio.json` num terminal. Como o manifesto pede administrador, o Windows mostra o pedido do UAC; para a corrida "sem administrador" do passo 2 usa o código-fonte com `uv`.

O ZIP não está assinado, por isso o Windows pode mostrar o aviso do SmartScreen ("O Windows protegeu o seu PC"): "Mais informações" e "Executar mesmo assim", depois de confirmares o SHA-256.

### O que observar com o PowerShell lançado pela ferramenta

A verificação lança o `powershell.exe` do Windows (caminho absoluto, `-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand`, ambiente construído de raiz) para tarefas, Defender, WMI, assinaturas e atalhos. Isto é uma forma de arranque que antivírus e EDRs vigiam. Decisão atual: manter `-EncodedCommand` (ver `docs/DECISIONS.md`, D-004). **Anota se houver qualquer reação**:

- O Microsoft Defender mostra uma deteção, um alerta ou bloqueia o PowerShell filho (vê Segurança do Windows, Proteção contra vírus e ameaças, Histórico de proteção).
- O SmartScreen ou o Controlo de Aplicações bloqueia o `ZeroBirus.exe`.
- Um EDR ou outro antivírus (qual?) alerta ou põe a ferramenta em quarentena.
- A verificação de tarefas, Defender, WMI ou assinaturas aparece como NAO_VERIFICADO com a razão "o PowerShell falhou" ou "excedeu".

Se houver reação, a alternativa já decidida é mudar a ponte de `-EncodedCommand` para `-File` com os scripts a ficar no disco numa pasta só de leitura da aplicação e com verificação do hash de cada script antes de os lançar. Diz-me o produto e a mensagem exatos.

## 1. Preparar a máquina

Usa uma VM com um snapshot, ou um PC que aceites ver analisado. Não instales nem desativeis nada: o objetivo é ver a máquina como ela é.

1. Instala o `uv` e o Git (instruções oficiais em https://docs.astral.sh/uv/). Isto só é preciso nesta fase de desenvolvimento.
2. Num terminal PowerShell:

```
git clone https://github.com/JPFerraZzz/ZeroBirus
cd ZeroBirus
git checkout phase-1/removable-suite   # ou main, depois de fundido
uv sync --locked
uv run zerobirus version
uv run zerobirus selftest
```

Estes dois últimos comandos correm em CI. O `uv sync` descarrega o Python 3.12 e as dependências da internet; é só desta preparação, o produto em si nunca faz pedidos de rede.

## 2. Correr a verificação duas vezes

**Sem administrador** (terminal normal):

```
uv run zerobirus scan --json --out sem-admin.json
```

**Com administrador** (terminal "Executar como administrador", na mesma pasta):

```
uv run zerobirus scan --json --out com-admin.json
```

Esperado: a segunda dá menos NAO_VERIFICADO do que a primeira (Defender, WMI, tarefas e ligações precisam de administrador). Se a primeira disser OK em alguma dessas, é um erro: anota.

Tempo esperado: de 30 s a poucos minutos. Cada verificação tem um limite de 240 s (cada chamada ao PowerShell, 120 s, com no máximo duas em simultâneo) e acaba como NAO_VERIFICADO se o ultrapassar. O relatório guarda os segundos de cada uma.

Sem `--json` o comando imprime um resumo em português no ecrã.

## 3. O que anotar

Cria uma nota por máquina com:

| Campo | Exemplo |
| --- | --- |
| Máquina | PC físico, VM (qual?), Windows 10 ou 11, versão |
| Estado conhecido | limpa, usada no dia a dia, suspeita de infeção, infetada de propósito |
| Antivírus | só Defender, outro (qual?) |
| Perfis de utilizador | quantos, com OneDrive? |
| Tempo | segundos totais e por verificação (campo `seconds`) |
| Resultado geral | OK, CONFERIR, SUSPEITO ou NAO_VERIFICADO, sem e com administrador |

E, para cada item que o relatório assinala:

- **Falso positivo**: sabes que é legítimo (programa, serviço, tarefa). Anota o nome, o fabricante e porque o conheces. Estes são os mais valiosos.
- **Verdadeiro positivo**: era mesmo mau, ou pelo menos indesejado.
- **Falso negativo**: sabes de algo mau ou suspeito na máquina que o relatório não mostra.
- **Estranho**: NAO_VERIFICADO sem motivo claro, tempos muito altos, nomes ou caminhos mal mostrados, texto em inglês onde devia estar português.

Verifica também, uma vez por tipo de máquina:

- Existe um processo "Memory Compression" no Gestor de Tarefas (separador Detalhes)? Se existir, o relatório tem de o conter (ver passo 5).
- O Defender está ativo, em modo passivo ou desligado? O relatório diz o mesmo?
- Se tens outro antivírus, o relatório diz "modo passivo" e não acusa "tempo real desligado"?

## 4. Antes de partilhar o relatório

O relatório sai já sem segredos e sem dados pessoais. Isto é uma rede de segurança, não uma garantia. **Abre o ficheiro e lê-o antes de o enviar.**

O que é removido ou substituído:

- Segredos em linhas de comando, URLs com credenciais, cabeçalhos de autorização, chaves e carteiras longas: aparecem como `[oculto]`. Num URL de pool como `stratum+tcp://utilizador:segredo@pool.exemplo:3333` ficam visíveis o utilizador, o servidor e a porta; só a palavra-passe fica oculta.
- Nomes de utilizador: `C:\Users\Maria` passa a `C:\Users\Utilizador1` (o mesmo nome dá sempre o mesmo número). Contas `MAQUINA\Utilizador1`; contas do sistema (`NT AUTHORITY`) ficam.
- O conteúdo das pastas pessoais (Documentos, Ambiente de trabalho, Imagens, Vídeos, Música, OneDrive) fica `[omitido]`. As Transferências (Downloads) ficam visíveis porque é lá que se encontram cracks.
- No relatório, as ligações de rede só incluem as que vão para portas de mineração.

O que pode ficar e tens de ver:

- O nome do computador, se aparecer fora de uma conta (por exemplo no ficheiro hosts ou num caminho de rede).
- Nomes de ficheiros e pastas que tenham nomes de pessoas fora das pastas pessoais.
- Endereços de e-mail ou nomes de contas dentro de linhas de comando.
- Nomes de programas que digam algo sobre ti.

Se encontrares algo, apaga-o à mão ou diz-me qual era o padrão para eu o acrescentar ao filtro.

## 5. Transformar o relatório numa fixture golden de falsos positivos

A secção `snapshot` do relatório tem o mesmo esquema que o backend fake lê. Para uma máquina que sabes que é legítima:

```
uv run python tools/report_to_fixture.py com-admin.json portatil-joao --kind false-positive
```

O que faz:

1. Valida o esquema e procura dados pessoais que tenham escapado (pastas de utilizador sem o marcador, e-mails, partilhas de rede, nomes de computador). Se encontrar, recusa e mostra o quê. Só com `--force`, depois de rever, escreve na mesma.
2. Escreve `tests/fixtures/recorded/portatil-joao.json` (a máquina) e `portatil-joao.expected.json` (o que a verificação diz hoje sobre ela).

Depois:

3. Abre o `.expected.json`. Cada linha é `[verificação, nível, item]`. Para uma máquina legítima o ideal é não haver SUSPEITO. Se houver, é um falso positivo: **não edites o ficheiro para o esconder**, diz-me, e corrigimos a regra. Os CONFERIR que entendes e aceitas podem ficar.
4. Corre `uv run pytest tests/golden tests/unit/test_recorded_machines.py`. O teste vai repetir a verificação sobre a fixture e comparar.
5. Faz commit dos dois ficheiros.

Para uma máquina infetada de propósito, usa `--kind detection`: o esperado passa a incluir os SUSPEITO que a ferramenta tem de continuar a encontrar.

As fixtures com processos reais de sistema também alimentam `tests/unit/test_recorded_machines.py`, que exige que System, Registry e Memory Compression estejam protegidos tal como o psutil os devolveu. Hoje o teste de Memory Compression **faz skip** porque o runner de CI não tem esse processo: assim que uma fixture sua entrar nesta pasta, deixa de fazer skip. Isto é a segunda razão para teres de recolher pelo menos uma máquina real.

## 6. Lista de aceitação manual da Fase 1

- [ ] `selftest` passa na máquina.
- [ ] A verificação acaba sem erros, sem e com administrador, em tempo razoável.
- [ ] Sem administrador, Defender, WMI, tarefas e ligações aparecem como NAO_VERIFICADO com motivo, e o resultado geral não é OK.
- [ ] Os itens que conheces como legítimos não estão como SUSPEITO. Os que estão como CONFERIR têm uma razão que percebes.
- [ ] "Coisas normais que assustam" mostra processos do sistema agrupados (por exemplo `svchost.exe (x40)`), não uma linha por processo.
- [ ] O relatório abre, lê-se e não tem dados pessoais (passo 4).
- [ ] Nenhum ficheiro, chave de registo, tarefa ou exclusão do Defender mudou. Podes conferir as pastas de Arranque, a chave Run do teu utilizador e a lista de exclusões do Defender antes e depois.
- [ ] Pelo menos uma fixture de uma máquina real foi gerada e o `pytest` passa com ela.
- [ ] (Opcional, só numa VM descartável) `tools/windows/make_test_artifacts.ps1` e depois `uv run zerobirus scan` mostram os artefactos inofensivos como SUSPEITO; `tools/windows/remove_test_artifacts.ps1` limpa tudo e uma nova verificação já não os mostra. No CI isto já corre automaticamente.

## 7. O que ainda não é coberto

Este plano não testa: remoção, quarentena, desfazer, ponto de restauro, o executável, a interface, a Análise do Defender nem o relatório final. Também não testa o comportamento com o Windows noutro idioma além do que a máquina tiver: a verificação não depende de texto traduzido (usa campos, códigos e enumerações), mas só uma máquina em outro idioma o prova. Se tiveres uma VM em inglês, é um teste útil.
