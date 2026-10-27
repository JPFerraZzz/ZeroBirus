# Auditoria adversarial da Fase 3 (remoção)

Âmbito: `src/zerobirus/remediation/engine.py`, `ops.py`, `cleanup.py`, `tempscan.py`, `platform/windows/remediator.py`, `scripts/remediate.ps1`, `platform/fake/ops.py` e a página da etapa 4. Método: ler o código como atacante (plano hostil, sistema hostil, pasta de sessão adulterável) e escrever o teste que o prova antes de corrigir. Feita pelo mesmo autor do código, por isso **não substitui uma revisão independente**; o João revê o diff com atenção (BRIEF, Fase 3).

## Encontrado e corrigido

| # | Problema | Correção | Teste |
| --- | --- | --- | --- |
| 1 | O plano usa o tipo de exclusão do Defender em pt-PT (`pasta`) e o motor esperava `path`: a ação era recusada. Apanhado pelo teste do PC com minerador. | Mapa único `EXCLUSION_KINDS` no plano, usado pelo motor e pelos backends. | `test_the_miner_machine_is_cleaned_verified_and_fully_undone` |
| 2 | Raiz de registo `HKU\\S-1-5-21-...` validada só por prefixo (`HKU\\S-1-5-21-1\\..\\..` passava). | Regex estrita da raiz. | `test_registry_roots_are_validated_strictly` |
| 3 | Tarefas do Defender (`\\Microsoft\\Windows\\Windows Defender\\`) podiam ser removidas se estivessem num plano. | Recusadas pela barreira do motor. | `test_antivirus_scheduled_tasks_are_never_removed` |
| 4 | Um registo de desfazer adulterado (escrita na pasta da sessão) podia mover qualquer ficheiro para qualquer sítio, ou apagar fora da quarentena. | O desfazer e o apagar só aceitam uma entrada direta da quarentena desta sessão; o destino é revalidado contra o `safety`. | `test_a_tampered_undo_record_cannot_move_arbitrary_files`, `test_a_tampered_record_cannot_delete_outside_the_quarantine` |
| 5 | O PID da própria ferramenta só era protegido pelo `own_pids` do contexto (calculado na verificação). | O motor recusa também `os.getpid()` e o PID pai. | `test_our_own_pid_is_never_terminated_even_if_the_context_forgot_it` |

## Barreiras verificadas por teste (já existiam no desenho)

- Item fora do plano autorizado, plano alterado depois de autorizado, id que não corresponde ao conteúdo: recusados (`NotAuthorized`) sem qualquer chamada ao sistema.
- Caminho protegido num plano autorizado: `IGNORADO`, nada movido.
- Link, junção, caminho que passa por uma junção, pasta com junção dentro: não seguidos, `IGNORADO` (testado com links simbólicos reais).
- PID reutilizado por outro programa, processo protegido: não terminados.
- Chaves de registo que não são de arranque, IPs privados, nomes que nunca se bloqueiam (microsoft.com...), linhas `localhost`: recusados.
- Informação para desfazer que não pode ser guardada: o item não é alterado.
- Ponto de restauro que falha: pára; só continua com confirmação explícita.
- Resultado só `REMOVIDO` ou `EM_QUARENTENA` depois de `verify()` reler o estado; um backend que "diz que fez" sem mudar nada dá `FALHOU`.
- Desfazer nunca substitui algo que entretanto apareceu no local original.
- `remediate.ps1`: verbos que alteram estado limitados a uma lista fixa; sem `iex`, `Invoke-*`, `Start-Process`, `Add-Type`; a ação escolhe-se numa lista fixa e todos os valores são dados passados a parâmetros.

## Riscos residuais (não corrigidos)

1. **TOCTOU**: entre a verificação do caminho e o `move` outro processo pode trocar o ficheiro por uma junção. Mitigação parcial: confirmamos a impressão digital do que ficou na quarentena contra a lida antes; não há abertura por handle sem seguir links. Aceite para a v1.
2. **Pasta da sessão**: fica em `%ProgramData%\\ZeroBirus`, e o ZeroBirus não define ACLs restritivas. A correção 4 limita o dano de um registo adulterado, mas um atacante com escrita ali ainda pode fazer o desfazer falhar, ou alterar o relatório. Passo seguinte: ACL só para administradores.
3. **Recriar assinaturas WMI no desfazer** só guarda propriedades simples (texto, números, booleanos); tipos exóticos podem falhar. Testado só no runner de CI.
4. **Restauro de tarefas** usa o XML exportado; tarefas que corriam com uma conta com palavra-passe podem não voltar.
5. **Ponto de restauro**: o Windows limita-o a um por 24 horas; o motor só o dá como criado se `Get-ComputerRestorePoint` o listar.
6. **Reativar o que o malware desligou** (Defender) não está implementado.
7. Nada disto foi testado em Windows real.
