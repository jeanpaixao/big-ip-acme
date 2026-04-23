#!/bin/bash
# =============================================================================
# bigip-acme-watch.sh — Watcher leve para Data Groups de domínios ACME
#
# Chamado pelo iCall handler a cada minuto.
# Só dispara bigip-acme.sh se o conteúdo dos Data Groups acme_* mudou
# desde a última execução. Usa MD5 do conteúdo como estado.
# =============================================================================

ACME_DIR="/shared/acme"
STATE_FILE="${ACME_DIR}/.dg_state"
LOG_FILE="${ACME_DIR}/logs/acme.log"
TMSH="/usr/bin/tmsh"
OBJECT_PREFIX="acme"
PARTITION="Common"
DATAGROUP_NAME="${OBJECT_PREFIX}_challenges"   # excluído do watch

# Carrega .env se existir
[[ -f "${ACME_DIR}/.env" ]] && source "${ACME_DIR}/.env"

log_watch() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [watch] $*" >> "${LOG_FILE}"
}

# Gera hash do conteúdo atual de todos os DGs acme_* exceto acme_challenges
current_hash=$(
    "${TMSH}" list ltm data-group internal 2>/dev/null | \
    awk -v part="${PARTITION}" -v prefix="${OBJECT_PREFIX}_" -v skip="${DATAGROUP_NAME}" '
        /^ltm data-group internal/ {
            name = $4
            sub("^/" part "/", "", name)
            in_target = (name ~ ("^" prefix) && name != skip)
        }
        in_target { print }
    ' | md5sum | awk '{print $1}'
)

# Se não conseguiu calcular o hash (tmsh indisponível etc.), sai silenciosamente
[[ -z "${current_hash}" ]] && exit 0

last_hash=$(cat "${STATE_FILE}" 2>/dev/null || echo "")

if [[ "${current_hash}" != "${last_hash}" ]]; then
    echo "${current_hash}" > "${STATE_FILE}"
    log_watch "Mudança detectada nos Data Groups. Acionando renovação..."
    "${ACME_DIR}/bigip-acme.sh" >> "${LOG_FILE}" 2>&1
    log_watch "Renovação concluída."
fi
