#!/usr/bin/env bash
#===============================================================================
# run_goose_pipeline.sh
#
# Orquestra toda a pipeline GOOSE IDS (rules2p4 -> p4c -> tofino-model ->
# switchd -> setup_rules -> tráfego -> bfshell interativo) em UM ÚNICO terminal.
#
#   - Tudo que hoje ocupa os terminais 1..5 roda em segundo plano.
#   - O terminal fica livre e, no fim, entrega o bfshell interativo pra você
#     digitar bfrt_python / hits().
#   - TODAS as saídas (inclusive as dos daemons e da sessão interativa) vão
#     para um único arquivo de log, separado por seção a cada execução.
#
# Uso:
#   ./run_goose_pipeline.sh                  # pergunta o arquivo de regras
#   ./run_goose_pipeline.sh rules_v2.py      # já passa o arquivo
#   ./run_goose_pipeline.sh -r rules_v3.py --verbose
#   ./run_goose_pipeline.sh --help
#===============================================================================

set -uo pipefail

#-------------------------------------------------------------------------------
# CONFIGURAÇÃO (pode ser sobrescrita por variável de ambiente)
#-------------------------------------------------------------------------------
CONV_DIR="${CONV_DIR:-/home/lucas/Documentos/Mestrado/Goose/Conversor}"
STUDIO_DIR="${STUDIO_DIR:-$HOME/open-p4studio}"
ENV_FILE="${ENV_FILE:-$HOME/setup-open-p4studio.bash}"
PROG="${PROG:-goose_ids}"
ARCH="${ARCH:-tofino}"

VETH_COUNT="${VETH_COUNT:-128}"
TRAFFIC_IFACE="${TRAFFIC_IFACE:-veth0}"
PCAP_OUT="${PCAP_OUT:-test_goose.pcap}"
VALIDATE_N="${VALIDATE_N:-100000}"

LOG_DIR="${LOG_DIR:-$CONV_DIR/logs}"
MASTER_LOG="${MASTER_LOG:-$LOG_DIR/goose_ids_pipeline.log}"

# Padrões usados para detectar que cada daemon subiu. Ajuste se a sua versão
# do SDE imprimir outra coisa (veja o log da seção pra descobrir).
MODEL_READY_RE='Server listening|Waiting for incoming|Starting servers|model.*ready'
SWITCHD_READY_RE='bfruntime gRPC server started|bf_switchd: server started|Starting UCLI|bfshell>'
READY_TIMEOUT="${READY_TIMEOUT:-180}"

#-------------------------------------------------------------------------------
# FLAGS
#-------------------------------------------------------------------------------
RULES=""
VERBOSE=false
SKIP_BUILD=false
STRICT_VALIDATE=false
SKIP_TRAFFIC=false
SKIP_BATCH_RULES=false
KEEP_ALIVE=false

usage() {
    sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
    cat <<EOF

Opções:
  -r, --rules FILE      Arquivo de regras (deve estar em $CONV_DIR)
      --skip-build      Pula rules2p4/validate/p4c (reaproveita o build atual)
      --strict-validate Aborta se validate.py acusar divergência (padrão: só avisa)
      --skip-traffic    Não gera nem reproduz tráfego de teste
      --skip-batch-rules  Não roda setup_rules.py em batch (só no bfshell interativo)
      --keep-alive      Deixa tofino-model e switchd rodando ao sair
  -v, --verbose         Mostra a saída completa na tela além de gravar no log
  -h, --help            Esta ajuda
EOF
}

while (( $# )); do
    case "$1" in
        -r|--rules)         RULES="${2:-}"; shift 2 ;;
        --skip-build)       SKIP_BUILD=true; shift ;;
        --strict-validate)  STRICT_VALIDATE=true; shift ;;
        --skip-traffic)     SKIP_TRAFFIC=true; shift ;;
        --skip-batch-rules) SKIP_BATCH_RULES=true; shift ;;
        --keep-alive)       KEEP_ALIVE=true; shift ;;
        -v|--verbose)       VERBOSE=true; shift ;;
        -h|--help)          usage; exit 0 ;;
        -*)                 echo "Opção desconhecida: $1"; usage; exit 1 ;;
        *)                  RULES="$1"; shift ;;
    esac
done

#-------------------------------------------------------------------------------
# CORES / HELPERS DE TELA
#-------------------------------------------------------------------------------
if [[ -t 1 ]]; then
    C_OK=$'\e[32m'; C_ERR=$'\e[31m'; C_WARN=$'\e[33m'; C_DIM=$'\e[2m'; C_B=$'\e[1m'; C_0=$'\e[0m'
else
    C_OK=""; C_ERR=""; C_WARN=""; C_DIM=""; C_B=""; C_0=""
fi
ts()   { date '+%Y-%m-%d %H:%M:%S'; }
info() { printf '%s\n' "$*"; }
warn() { printf '%s!! %s%s\n' "$C_WARN" "$*" "$C_0"; }

# Alguns scripts do SDE (e o prompt de senha do sudo) mexem na linha de
# disciplina do TTY e deixam a saída "em escada". Guardamos o estado original
# e restauramos depois de cada passo.
TTY_STATE=""
[[ -t 0 ]] && TTY_STATE="$(stty -g 2>/dev/null)"
tty_restore() {
    [[ -t 0 ]] || return 0
    if [[ -n "$TTY_STATE" ]]; then stty "$TTY_STATE" 2>/dev/null || stty sane 2>/dev/null
    else stty sane 2>/dev/null; fi
    return 0
}

#-------------------------------------------------------------------------------
# 1) ARQUIVO DE REGRAS
#-------------------------------------------------------------------------------
[[ -d "$CONV_DIR" ]] || { echo "Pasta do conversor não encontrada: $CONV_DIR"; exit 1; }

if [[ -z "$RULES" ]]; then
    echo
    echo "${C_B}Arquivos de regras disponíveis em $CONV_DIR:${C_0}"
    ( cd "$CONV_DIR" && ls -1 rules*.py 2>/dev/null | sed 's/^/   - /' ) || true
    echo
    read -r -e -p "Arquivo de regras [rules_v1.py]: " RULES
    RULES="${RULES:-rules_v1.py}"
fi

RULES="$(basename "$RULES")"                 # garante que é da pasta do conversor
[[ "$RULES" == *.py ]] || RULES="${RULES}.py"
RULES_PATH="$CONV_DIR/$RULES"
RULES_TAG="${RULES%.py}"                     # ex.: rules_v1

if [[ ! -f "$RULES_PATH" ]]; then
    echo "${C_ERR}Arquivo não encontrado: $RULES_PATH${C_0}"
    echo "Ele precisa estar na pasta do conversor."
    exit 1
fi

#-------------------------------------------------------------------------------
# 2) LOG: abertura da seção
#-------------------------------------------------------------------------------
STAMP="$(date '+%Y%m%d_%H%M%S')"
TMP_DIR="$LOG_DIR/.run_$STAMP"
mkdir -p "$LOG_DIR" "$TMP_DIR"
MODEL_LOG="$TMP_DIR/tofino_model.log"
SWITCHD_LOG="$TMP_DIR/switchd.log"
BFSHELL_LOG="$TMP_DIR/bfshell_session.log"

{
    echo
    echo "==============================================================================="
    echo "------- Inicio log $RULES_TAG ----"
    echo "  Data......: $(ts)"
    echo "  Host......: $(hostname)  |  Usuário: $USER"
    echo "  Regras....: $RULES_PATH"
    echo "  Programa..: $PROG ($ARCH)"
    echo "  Comando...: $0 $*"
    echo "==============================================================================="
} >> "$MASTER_LOG"

log_raw() { cat >> "$MASTER_LOG"; }

merge_log() {   # merge_log "TÍTULO" arquivo
    local title="$1" file="$2"
    [[ -s "$file" ]] || return 0
    {
        echo
        echo "--------------------------------------------------------------"
        echo "[$(ts)] SAÍDA COMPLETA: $title"
        echo "--------------------------------------------------------------"
        cat "$file"
    } >> "$MASTER_LOG"
}

#-------------------------------------------------------------------------------
# 3) LIMPEZA / ENCERRAMENTO DA SEÇÃO
#-------------------------------------------------------------------------------
MODEL_PID=""; SWITCHD_PID=""; SUDO_PID=""
FINISHED=false

stop_pid() {  # stop_pid <pid> <nome>
    local pid="$1" name="$2"
    [[ -n "$pid" ]] || return 0
    kill -0 "$pid" 2>/dev/null || return 0
    printf '  parando %-20s' "$name..."
    kill -TERM -"$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null
    for _ in {1..10}; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    kill -0 "$pid" 2>/dev/null && { kill -KILL -"$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null; }
    printf '%sok%s\n' "$C_OK" "$C_0"
}

cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    tty_restore
    echo
    if $KEEP_ALIVE; then
        warn "--keep-alive: tofino-model (PID $MODEL_PID) e switchd (PID $SWITCHD_PID) continuam rodando."
    else
        stop_pid "$SWITCHD_PID" "switchd"
        stop_pid "$MODEL_PID"   "tofino-model"
    fi
    [[ -n "$SUDO_PID" ]] && kill "$SUDO_PID" 2>/dev/null

    merge_log "TOFINO MODEL"              "$MODEL_LOG"
    merge_log "SWITCHD"                   "$SWITCHD_LOG"
    merge_log "BFSHELL (sessão interativa)" "$BFSHELL_LOG"
    {
        echo
        echo "[$(ts)] Encerrado com status $rc"
        echo "--- Final log $RULES_TAG ---"
        echo
    } >> "$MASTER_LOG"

    rm -rf "$TMP_DIR"
    echo "${C_DIM}Log da seção gravado em: $MASTER_LOG${C_0}"
    exit $rc
}
trap cleanup EXIT INT TERM

#-------------------------------------------------------------------------------
# 4) EXECUÇÃO DE PASSOS
#-------------------------------------------------------------------------------
STEP_N=0
LAST_RC=0
step() {   # step "título" 'comando' [soft]
    local title="$1" cmd="$2" soft="${3:-}"
    STEP_N=$((STEP_N + 1))
    {
        echo
        echo "--------------------------------------------------------------"
        echo "[$(ts)] PASSO $STEP_N: $title"
        echo "\$ $cmd"
        echo "--------------------------------------------------------------"
    } >> "$MASTER_LOG"

    local rc t0=$SECONDS
    if $VERBOSE; then
        printf '  [%02d] %s\n' "$STEP_N" "$title"
        ( eval "$cmd" ) 2>&1 | tee -a "$MASTER_LOG"
        rc=${PIPESTATUS[0]}
        tty_restore
        printf '       -> '
    else
        printf '  [%02d] %-50s' "$STEP_N" "$title"
        ( eval "$cmd" ) >> "$MASTER_LOG" 2>&1
        rc=$?
        tty_restore
    fi
    LAST_RC=$rc

    if (( rc == 0 )); then
        printf '%sok%s %s(%ds)%s\n' "$C_OK" "$C_0" "$C_DIM" "$((SECONDS - t0))" "$C_0"
    else
        printf '%sFALHOU (rc=%d)%s\n' "$C_ERR" "$rc" "$C_0"
        echo "[$(ts)] PASSO $STEP_N FALHOU (rc=$rc)" >> "$MASTER_LOG"
        if [[ "$soft" != "soft" ]]; then
            echo "      veja os detalhes em: $MASTER_LOG"
            exit "$rc"
        fi
    fi
    return 0
}

start_bg() {   # start_bg <logfile> 'comando'  -> ecoa o PID
    local logf="$1" cmd="$2"
    setsid bash -c "$cmd" > "$logf" 2>&1 < /dev/null &
    echo $!
}

wait_ready() {   # wait_ready <pid> <logfile> <regex> <nome>
    local pid="$1" logf="$2" re="$3" name="$4" t=0
    printf '       aguardando %s ficar pronto' "$name"
    while (( t < READY_TIMEOUT )); do
        if grep -Eq "$re" "$logf" 2>/dev/null; then
            printf ' %sok%s (%ds)\n' "$C_OK" "$C_0" "$t"; return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            printf ' %smorreu!%s\n' "$C_ERR" "$C_0"
            tail -n 30 "$logf"
            return 2
        fi
        sleep 1; t=$((t + 1))
        (( t % 5 == 0 )) && printf '.'
    done
    printf ' %stimeout%s (segue mesmo assim)\n' "$C_WARN" "$C_0"
    return 1
}

#-------------------------------------------------------------------------------
# 5) PREPARO: ambiente + sudo
#-------------------------------------------------------------------------------
echo
echo "${C_B}=== Pipeline GOOSE IDS — $RULES_TAG ===${C_0}"
echo "${C_DIM}log unificado: $MASTER_LOG${C_0}"
echo

if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$ENV_FILE" >> "$MASTER_LOG" 2>&1
else
    echo "${C_ERR}Arquivo de ambiente não encontrado: $ENV_FILE${C_0}"; exit 1
fi
: "${SDE:?SDE não definido após carregar $ENV_FILE}"
: "${SDE_INSTALL:?SDE_INSTALL não definido após carregar $ENV_FILE}"
{
    echo "SDE.........: $SDE"
    echo "SDE_INSTALL.: $SDE_INSTALL"
} | tee -a "$MASTER_LOG"

P4_SRC_DIR="$HOME/open-p4studio/pkgsrc/p4-examples/p4_16_programs/$PROG"
BUILD_DIR="$CONV_DIR/build"
SETUP_RULES="$BUILD_DIR/setup_rules.py"

echo
echo "${C_DIM}(sudo é usado para veth_setup e tcpreplay)${C_0}"
sudo -v || { echo "sudo negado"; exit 1; }
tty_restore
( while true; do sudo -n true; sleep 50; kill -0 "$$" 2>/dev/null || exit; done ) 2>/dev/null &
SUDO_PID=$!

#-------------------------------------------------------------------------------
# 6) FASE 1 — veths + build (antigo terminal 1)
#-------------------------------------------------------------------------------
echo
echo "${C_B}[1/5] Ambiente e build${C_0}"

step "Criando interfaces veth ($VETH_COUNT)" \
     'sudo "$SDE_INSTALL/bin/veth_setup.sh" '"$VETH_COUNT"

step "Conferindo veth0" \
     'ip link show '"$TRAFFIC_IFACE"' >/dev/null 2>&1 && echo "veths OK"'

if $SKIP_BUILD; then
    warn "--skip-build: pulando rules2p4 / validate / p4c"
else
    step "Convertendo regras ($RULES -> P4)" \
         'cd "$CONV_DIR" && python3 rules2p4.py "'"$RULES"'" -o build --prog "$PROG" --report'

    if $STRICT_VALIDATE; then
        step "Validando regras (n=$VALIDATE_N, estrito)" \
             'cd "$CONV_DIR" && python3 validate.py "'"$RULES"'" -n '"$VALIDATE_N"
    else
        step "Validando regras (n=$VALIDATE_N)" \
             'cd "$CONV_DIR" && python3 validate.py "'"$RULES"'" -n '"$VALIDATE_N" soft
        if (( LAST_RC != 0 )); then
            warn "validate.py reportou divergências (rc=$LAST_RC) — seguindo mesmo assim."
            tac "$MASTER_LOG" | grep -m1 'divergência detecção' | sed 's/^/       /' || true
            echo "       ${C_DIM}(use --strict-validate para abortar nesse caso)${C_0}"
        fi
    fi

    step "Copiando ${PROG}.p4 para o open-p4studio" \
         'mkdir -p "$P4_SRC_DIR" && cp "$BUILD_DIR/$PROG.p4" "$P4_SRC_DIR/"'

    step "Compilando com p4c (tofino/tna)" \
         'mkdir -p "$SDE_INSTALL/share/tofinopd/$PROG" && \
          p4c --target tofino --arch tna \
              --program-name "$PROG" \
              --bf-rt-schema "$SDE_INSTALL/share/tofinopd/$PROG/bf-rt.json" \
              -o "$SDE_INSTALL/share/tofinopd/$PROG" \
              "$P4_SRC_DIR/$PROG.p4"'

    step "Listando artefatos gerados" \
         'ls -la "$SDE_INSTALL/share/tofinopd/$PROG/"' soft

    step "Verificando .conf e artefatos obrigatórios" \
         'python3 -m json.tool "$SDE_INSTALL/share/p4/targets/tofino/$PROG.conf" >/dev/null && echo "JSON ok"
          for f in bf-rt.json pipe/context.json pipe/tofino.bin; do
              if [ -f "$SDE_INSTALL/share/tofinopd/$PROG/$f" ]; then echo "ok    $f"
              else echo "FALTA $f"; fi
          done' soft
fi

#-------------------------------------------------------------------------------
# 7) FASE 2 — tofino-model + switchd em segundo plano (terminais 3 e 4)
#-------------------------------------------------------------------------------
echo
echo "${C_B}[2/5] Subindo o plano de dados${C_0}"

if pgrep -f 'tofino-model' >/dev/null 2>&1; then
    warn "já existe um tofino-model rodando — reaproveitando (não vou subir outro)."
else
    printf '  [--] %-50s' "tofino-model (background)"
    MODEL_PID=$(start_bg "$MODEL_LOG" "cd '$STUDIO_DIR' && source '$ENV_FILE' >/dev/null 2>&1; ./run_tofino_model.sh -p '$PROG' --arch '$ARCH'")
    printf '%sPID %s%s\n' "$C_OK" "$MODEL_PID" "$C_0"
    wait_ready "$MODEL_PID" "$MODEL_LOG" "$MODEL_READY_RE" "tofino-model" || true
fi

if pgrep -f 'bf_switchd' >/dev/null 2>&1; then
    warn "já existe um bf_switchd rodando — reaproveitando."
else
    printf '  [--] %-50s' "switchd (background)"
    SWITCHD_PID=$(start_bg "$SWITCHD_LOG" "cd '$STUDIO_DIR' && source '$ENV_FILE' >/dev/null 2>&1; ./run_switchd.sh -p '$PROG' --arch '$ARCH'")
    printf '%sPID %s%s\n' "$C_OK" "$SWITCHD_PID" "$C_0"
    wait_ready "$SWITCHD_PID" "$SWITCHD_LOG" "$SWITCHD_READY_RE" "switchd" || true
fi
sleep 3   # respiro para o gRPC do BF-Runtime abrir de fato

#-------------------------------------------------------------------------------
# 8) FASE 3 — carga das regras em batch (terminal 2)
#-------------------------------------------------------------------------------
echo
echo "${C_B}[3/5] Populando as tabelas${C_0}"

if $SKIP_BATCH_RULES; then
    warn "--skip-batch-rules: as regras serão carregadas só na sessão interativa."
elif [[ -f "$SETUP_RULES" ]]; then
    step "bfshell -b setup_rules.py" \
         'cd "$STUDIO_DIR" && ./run_bfshell.sh -b "$SETUP_RULES"' soft
else
    warn "não achei $SETUP_RULES — pulei a carga em batch."
fi

#-------------------------------------------------------------------------------
# 9) FASE 4 — tráfego de teste (terminal 5)
#-------------------------------------------------------------------------------
echo
echo "${C_B}[4/5] Tráfego de teste${C_0}"

if $SKIP_TRAFFIC; then
    warn "--skip-traffic: nenhum pacote será injetado."
else
    step "Gerando PCAP a partir de $RULES" \
         'cd "$CONV_DIR" && python3 gen_test_traffic.py "'"$RULES"'" -o "$PCAP_OUT"'

    step "Interfaces veth ativas" \
         'ip -br link show | grep veth | head' soft

    step "Reproduzindo tráfego em $TRAFFIC_IFACE" \
         'cd "$CONV_DIR" && sudo tcpreplay -i "'"$TRAFFIC_IFACE"'" "$PCAP_OUT"' soft
fi

#-------------------------------------------------------------------------------
# 10) FASE 5 — bfshell interativo (terminal 6) — fica em primeiro plano
#-------------------------------------------------------------------------------
SNIPPET="bfrt_python
d = bfrt.${PROG}.pipe.Ingress.detect
exec(open('${SETUP_RULES}').read())
hits()"

echo
echo "${C_B}[5/5] bfshell interativo${C_0}"
cat <<EOF

${C_DIM}Tudo que estava nos terminais 1–5 já rodou. Agora é com você.
Cole no prompt do bfshell (a sessão inteira vai para o log):${C_0}

${C_B}${SNIPPET}${C_0}

${C_DIM}Saia com Ctrl+D (ou 'quit') para encerrar a seção e fechar o log.${C_0}
EOF

{
    echo
    echo "[$(ts)] Snippet sugerido para a sessão interativa:"
    echo "$SNIPPET"
} >> "$MASTER_LOG"

read -r -p "Pressione ENTER para abrir o bfshell... " _ || true
cd "$STUDIO_DIR" || exit 1
script -q -c "./run_bfshell.sh" "$BFSHELL_LOG"
tty_restore

FINISHED=true
echo
echo "${C_OK}Pipeline concluída para $RULES_TAG.${C_0}"
