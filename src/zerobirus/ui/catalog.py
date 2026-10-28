"""All user-facing text, in one place, pt-PT (BRIEF section 17: a catalogue so English can follow).

Text that comes from the machine (names, paths, command lines) never goes through here: it is
data and is shown as plain text only.
"""

from __future__ import annotations

from zerobirus.core.context import Symptom
from zerobirus.core.models import Level

APP_NAME = "ZeroBirus"
SIGNATURE = "by Ferraz"

STAGES: tuple[tuple[str, str], ...] = (
    ("context", "Contexto"),
    ("verify", "Verificação"),
    ("diagnosis", "Diagnóstico"),
    ("authorize", "Autorização"),
    ("removal", "Remoção"),
    ("confirm", "Confirmação"),
    ("after", "Depois"),
)

STAGE_LEAD = {
    "context": "Vamos começar por perceber o que notaste no PC. Isto só muda a ordem e o destaque das verificações; nenhuma é desligada.",
    "verify": "O ZeroBirus vai ler o PC para ver o que está a correr e o que arranca com o Windows. Nesta etapa não muda nada.",
    "diagnosis": "Este é o resultado da leitura. Nada foi alterado. Podes ver mais detalhe de cada item antes de decidir.",
    "authorize": "Escolhe o que queres remover. Só o que autorizares aqui pode ser alterado, e remover é mover para a quarentena: dá para desfazer.",
    "removal": "O ZeroBirus vai fazer, por esta ordem, só o que autorizaste. Cada passo é confirmado depois de feito.",
    "confirm": "Vamos repetir a verificação e ver o que mudou, e depois analisar com o Microsoft Defender.",
    "after": "O que fazer a seguir para o PC e as tuas contas ficarem seguros.",
}

SYMPTOM_LABELS = {
    Symptom.SLOW: "O PC está lento",
    Symptom.HOT: "O PC aquece muito",
    Symptom.FAN: "A ventoinha trabalha a fundo com o PC parado",
    Symptom.WINDOWS_FLASH: "Abre e fecha janelas sozinho",
    Symptom.ANTIVIRUS_OFF: "O antivírus apareceu desligado",
    Symptom.PIRATED: "Instalei um programa pirata ou um crack",
    Symptom.OTHER: "Outra coisa",
}

ADMIN_OK = "O ZeroBirus está a correr como administrador."
ADMIN_MISSING = (
    "O ZeroBirus não está a correr como administrador. Sem isso não consegue ler o Defender, "
    "as assinaturas WMI nem todas as tarefas, e essas verificações ficam por fazer."
)
ADMIN_RESTART = "Reiniciar como administrador"
ADMIN_RESTART_DISABLED_DEMO = "Não disponível no modo de demonstração."

CHECK_TITLE = {
    "processes": "Processos em execução",
    "startup": "Arranque com o Windows",
    "tasks": "Tarefas agendadas",
    "services": "Serviços",
    "files": "Programas em pastas graváveis",
    "network": "Ligações de rede",
    "defender": "Microsoft Defender",
    "hosts": "Ficheiro hosts",
    "wmi_bindings": "Assinaturas WMI",
}
CHECK_SIMPLE = {
    "processes": "Vou ver que programas estão a correr, de que pasta correm e quanto processador usam.",
    "startup": "Vou ver o que arranca sozinho com o Windows: registo, pastas de Arranque e outros pontos.",
    "tasks": "Vou ver as tarefas agendadas, incluindo as que se disfarçam com nomes da Microsoft.",
    "services": "Vou ver os serviços que não são da Microsoft e de onde correm.",
    "files": "Vou procurar programas em pastas onde o utilizador pode escrever, como AppData e Temp.",
    "network": "Vou ver que programas têm ligações abertas a portas usadas por pools de mineração.",
    "defender": "Vou ver o estado do Microsoft Defender, o histórico de ameaças e as exclusões.",
    "hosts": "Vou ver se o ficheiro hosts redireciona sites de segurança ou de atualizações.",
    "wmi_bindings": "Vou ver se há assinaturas WMI permanentes que executam comandos sozinhas.",
}
CHECK_TECH = {
    "processes": "psutil: nome, caminho, linha de comando, utilizador, processo pai; CPU em 3 leituras; assinatura Authenticode só dos candidatos.",
    "startup": "winreg: Run, RunOnce, Policies\\Explorer\\Run (HKLM e utilizadores com sessão, vistas de 32 e 64 bits), Winlogon, AppInit_DLLs, IFEO, pastas de Arranque.",
    "tasks": "PowerShell Get-ScheduledTask (pasta, nome, estado, ações, gatilhos).",
    "services": "winreg: HKLM\\SYSTEM\\CurrentControlSet\\Services e a assinatura do binário.",
    "files": "os.scandir limitado em profundidade, entradas e tempo; não segue junções nem links.",
    "network": "psutil.net_connections: ligações ativas com o processo. Sem DNS nem pedidos de rede.",
    "defender": "PowerShell Get-MpComputerStatus, Get-MpPreference e Get-MpThreat.",
    "hosts": "Leitura de %SystemRoot%\\System32\\drivers\\etc\\hosts.",
    "wmi_bindings": "PowerShell Get-CimInstance em root\\subscription (filtros, consumidores, ligações).",
}

LEVEL_WORD = {
    Level.SUSPEITO: "SUSPEITO",
    Level.CONFERIR: "CONFERIR",
    Level.OK: "OK",
    Level.NAO_VERIFICADO: "NÃO VERIFICADO",
}
LEVEL_EXPLAIN = {
    Level.SUSPEITO: "Há provas fortes de que isto não devia estar aqui.",
    Level.CONFERIR: "Pode ser legítimo ou não. Vê o detalhe e decide.",
    Level.OK: "Confirmado como legítimo.",
    Level.NAO_VERIFICADO: "Esta verificação não correu ou ficou incompleta. Não conta como OK.",
}

BTN_START_SCAN = "&Começar a verificação"
BTN_CANCEL_SCAN = "&Cancelar"
BTN_BACK = "&Voltar"
BTN_NEXT = "&Seguinte"
BTN_SEE_DIAGNOSIS = "Ver o &diagnóstico"
BTN_TO_AUTHORIZE = "Continuar para a &autorização"
BTN_SHOW_DETAIL = "Mostrar detalhe &técnico"
BTN_HIDE_DETAIL = "Esconder detalhe &técnico"
BTN_KEEP_ALL = "&Manter tudo"
BTN_REMOVE_N = "&Remover os {n} itens da lista"
BTN_REMOVE_ONE = "&Remover o item da lista"
BTN_COPY_REPORT = "Copiar relatório para a &pen"

DECISION_REMOVE = "Remover"
DECISION_KEEP = "Manter"

HDR_ITEM = "Item"
HDR_WHERE = "Onde está"
HDR_LEVEL = "Nível"
HDR_WHAT = "O que é"

PROGRESS_TEXT = "{done} de {total} verificações concluídas"
PROGRESS_NO_ANIMATION = "A trabalhar..."
SCAN_DONE = "Verificação concluída. Nada foi alterado."
SCAN_CANCELLED = "Verificação cancelada. Nada foi alterado."
SCAN_FAILED = "A verificação não pôde correr: {reason}"

DIAG_NOTHING = "Não encontrei nada que precise de ser removido."
DIAG_NOT_VERIFIED_TITLE = "Não foi possível verificar"
DIAG_NORMAL_TITLE = "Coisas normais que assustam"
DIAG_THREAT_TITLE = "Ameaça provável"
DIAG_ENTRY_TITLE = "Por onde pode ter entrado"
DIAG_INDICATORS_TITLE = "Indicadores para investigação (dados do atacante)"
DIAG_WHY_TITLE = "Porque é que aparece"
DIAG_SELECT_HINT = "Escolhe uma linha para ver o detalhe."

AUTH_QUESTION = "Posso remover tudo isto?"
AUTH_INTRO_SUSPECT = "Itens suspeitos: vêm marcados para remover. Podes mudar."
AUTH_INTRO_CONFER = "Itens para conferir: nunca vêm marcados. Decide um a um."
AUTH_ACK = "Li a lista e percebo que estes itens vão para a quarentena."
AUTH_EXTRA = "O plano é grande. Escreve o número de itens para confirmar ({n}):"
AUTH_NONE_SELECTED = "Não escolheste nenhum item para remover."
AUTH_SUMMARY = "Vão ser alterados {n} itens: {parts}."
AUTH_NOT_PLANNABLE = "O ZeroBirus não vai tocar nestes achados"
AUTH_PLAN_SAVED = "O plano ficou guardado em: {path}"
AUTH_PLAN_NOT_SAVED = (
    "Não foi possível guardar o plano no Ambiente de trabalho ({reason}). Nada foi alterado."
)

PLACEHOLDER_LATER = "Esta etapa fica disponível quando a etapa anterior estiver concluída."

# Stage 4: removal
REMOVAL_RUNNING = "A criar o ponto de restauro e a guardar o que é preciso para desfazer. Depois, um passo de cada vez."
REMOVAL_NO_RESTORE = (
    "Não foi possível criar um ponto de restauro: {reason}\n\n"
    "Podes continuar sem ele. Remover é mover para a quarentena e dá para desfazer, mas sem o "
    "ponto de restauro o Windows não te deixa voltar atrás de uma só vez."
)
REMOVAL_FAILED = "A remoção parou por um erro: {reason}. Nada mais foi alterado."
REMOVAL_SUMMARY = "{done} feitos e confirmados, {failed} falharam, {ignored} não foram tocados. Ponto de restauro: {restore}."
BTN_GO_ON_WITHOUT_RESTORE = "Continuar &sem ponto de restauro"
BTN_STOP_NOTHING_CHANGED = "&Parar (nada foi alterado)"
BTN_UNDO_ITEM = "&Desfazer"
BTN_UNDO_ALL = "Desfazer &tudo"
BTN_DELETE_QUARANTINE = "Apagar a quarentena de &vez..."
BTN_CONTINUE_CONFIRM = "Continuar para a &confirmação"
DELETE_QUARANTINE_ASK = (
    "Apagar de vez o que está na quarentena?\n\nDepois disto NÃO dá para desfazer esses itens."
)
RESULT_LABEL = {
    "REMOVIDO": "Feito e confirmado",
    "EM_QUARENTENA": "Em quarentena",
    "FALHOU": "Falhou",
    "PENDENTE_REINICIO": "Falta reiniciar",
    "IGNORADO": "Não foi tocado",
}
AUTH_INTRO_TEMP = (
    "Opcional: ficheiros temporários antigos. Não são ameaças; libertam espaço. Vêm desmarcados "
    "e vão para a quarentena como tudo o resto."
)

# Stage 5 and 6
CONFIRM_RESCAN = "&Repetir a verificação"
CONFIRM_RESCANNING = "A repetir a verificação..."
CONFIRM_DEFENDER = "&Analisar com o Microsoft Defender"
CONFIRM_DEFENDER_NOTE = (
    "A análise completa pode demorar horas e continua mesmo que feches esta janela. "
    "O fim só é dado como certo quando o Defender o regista."
)
CONFIRM_RESTART = "Reiniciar o &PC..."
CONFIRM_RESTART_ASK = (
    "Reiniciar o PC daqui a 30 segundos?\n\nGuarda o que tens aberto. Quando voltares a abrir o "
    "ZeroBirus, ele oferece a verificação pós-reinício."
)
CONFIRM_OFFLINE = (
    "Se ainda houver dúvidas, faz a Análise offline do Microsoft Defender (Segurança do Windows, "
    "Proteção contra vírus e ameaças, Opções de análise). Reinicia o PC, por isso só quando "
    "puderes."
)
CONFIRM_CLEAN = "Não há nada suspeito e tudo foi verificado."
CONFIRM_NOT_CLEAN = "Ainda há itens suspeitos ou verificações por completar. Lê a lista."
BTN_TO_AFTER = "Continuar para o &fim"
BTN_SAVE_FINAL = "&Guardar o relatório final"
BTN_CLEAN_WORK = "&Apagar a pasta de trabalho..."
CLEAN_WORK_ASK = (
    "Apagar a quarentena e a informação para desfazer deste PC?\n\nOs relatórios ficam. Depois "
    "disto NÃO dá para desfazer a limpeza."
)
PENDING_RESTART = "Há uma verificação pós-reinício por fazer (sessão {sid})."
BTN_POST_RESTART = "Fazer a verificação &pós-reinício"

# Home menu (docs/DESIGN.md 3.11). The last entry is the deep analysis, always at the bottom.
HOME_TITLE = "O que queres fazer?"
HOME_LEAD = (
    "Escolhe uma opção. Nada é alterado sem o autorizares e tudo o que se remove pode ser desfeito."
)
HOME_BACK = "← Menu inicial"
HOME_SOON = "Em breve"
HOME_SOON_NOTE = "Esta função chega numa versão seguinte."
HOME_DEEP = "deep"
# key, title, one plain sentence, available now
HOME_CARDS: tuple[tuple[str, str, str, bool], ...] = (
    ("clean", "Limpeza", "Apaga lixo, temporários e caches. Vês quanto espaço libertas.", False),
    ("game", "FPS / Modo jogo", "Prepara o PC para jogar. Mudanças pequenas e reversíveis.", False),
    ("startup", "Arranque", "Vê o que arranca com o Windows e desativa o que não queres.", False),
    ("apps", "Atualizar apps", "Atualiza os teus programas, uns a uns ou todos de uma vez.", False),
    (
        "drivers",
        "Drivers",
        "Vê a versão dos drivers e abre as páginas certas para atualizar.",
        False,
    ),
)
HOME_DEEP_TITLE = "Análise profunda"
HOME_DEEP_LEAD = (
    "Procura mineradores de criptomoeda, trojans e outro malware. Mostra tudo o que encontra "
    "e só remove o que autorizares."
)

# Collapsible groups on the authorisation page (docs/DESIGN.md 3.12).
GROUP_OPEN_ALL = "&Abrir tudo"
GROUP_CLOSE_ALL = "&Fechar tudo"
GROUP_HEADER = "{arrow}  {title}  ({n} {itens}, {k} para remover)"
