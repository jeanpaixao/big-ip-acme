#!/bin/bash
# =============================================================================
# bigip-acme.sh — Renovação automática de certificados ACME para F5 BIG-IP
#
# Fluxo:
#   1. Baixa o dehydrated (cliente ACME em bash) se não existir
#   2. Usa Data Groups do BIG-IP para mapear domínios → VS HTTPS
#   3. Hook usa iRule + Data Group para responder o challenge HTTP-01
#   4. Instala o certificado via tmsh e associa ao VS HTTPS automaticamente
#
# Uso:
#   ./bigip-acme.sh --setup --vs /Common/vs_http --vs-https /Common/vs_https
#   ./bigip-acme.sh         (renovação — rode via cron, descobre tudo do BIG-IP)
#   ./bigip-acme.sh --help
#
# Opções:
#   --setup              Configuração inicial (idempotente)
#   --vs <nome>          VS HTTP (porta 80) que receberá a iRule de challenge.
#                        Pode ser repetido para múltiplos VSes.
#   --vs-https <nome>    VS HTTPS para o qual criar o Data Group de domínios.
#                        Pode ser repetido. O Data Group criado é:
#                        acme_<vs_name_sanitizado>
#   --dest <ip:porta>    Cria um VS dedicado na porta 80 (usado sem --vs)
#   --staging            Usa CA de staging do Let's Encrypt (sem rate-limit)
#   --help               Exibe esta ajuda
#
# Estrutura dos Data Groups de domínios:
#   Um DG por VS HTTPS, nomeado: acme_<vs_name_sanitizado>
#   Registro especial:  _vs_https  →  /Common/nome_do_vs_https
#   Registros de domínio: chave = "dominio.com [san1 san2 ...]"
#                         valor = vazio (ou descrição livre)
#
# Exemplos:
#   # Setup: VS HTTP para challenge + VS HTTPS para o cert
#   ./bigip-acme.sh --setup \
#       --vs /Common/meuvs_http-redirect \
#       --vs-https /Common/meuvs_http-redirect
#
#   # Adicionar domínios ao Data Group criado:
#   tmsh modify ltm data-group internal /Common/acme_meuvs_http-redirect \
#       records add { "waf.exemplo.com.br" { data "" } }
#
#   # Adicionar domínio com SANs:
#   tmsh modify ltm data-group internal /Common/acme_meuvs_http-redirect \
#       records add { "exemplo.com.br www.exemplo.com.br" { data "" } }
#
#   # Renovação via cron (sem argumentos — descobre DGs automaticamente)
#   0 3 * * 1 /shared/acme/bigip-acme.sh >> /shared/acme/logs/acme.log 2>&1
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURAÇÃO — edite este bloco
# =============================================================================

ACME_DIR="/shared/acme"

# E-mail pode vir de três formas (ordem de prioridade):
#   1. Variável de ambiente:  export ACME_EMAIL=admin@empresa.com.br
#   2. Arquivo /shared/acme/.env contendo: ACME_EMAIL=admin@empresa.com.br
#   3. Valor hardcoded abaixo (deixe vazio se usar uma das opções acima)
CONTACT_EMAIL="${ACME_EMAIL:-}"

# CA de produção do Let's Encrypt
CA="https://acme-v02.api.letsencrypt.org/directory"
# Para testes sem rate-limit, comente a linha acima e descomente abaixo:
# CA="https://acme-staging-v02.api.letsencrypt.org/directory"

# VS HTTP (porta 80) para o challenge — pode ser sobrescrito via --vs
ACME_VS_NAME=""        # ex: "/Common/vs_http_80"
ACME_VS_DESTINATION="" # ex: "10.0.0.1:80" (usado para criar VS dedicado)

# Partição padrão
PARTITION="Common"

# Prefixo dos objetos criados pelo script no BIG-IP
OBJECT_PREFIX="acme"

# =============================================================================
# CONSTANTES
# =============================================================================

TMSH="/usr/bin/tmsh"
DEHYDRATED="${ACME_DIR}/dehydrated"
HOOK_SCRIPT="${ACME_DIR}/bigip-hook.sh"
CERTS_DIR="${ACME_DIR}/certs"
LOG_DIR="${ACME_DIR}/logs"
IRULE_NAME="${OBJECT_PREFIX}_challenge_handler"
DATAGROUP_NAME="${OBJECT_PREFIX}_challenges"
DEHYDRATED_URL="https://raw.githubusercontent.com/dehydrated-io/dehydrated/master/dehydrated"
DEHYDRATED_CONF="${ACME_DIR}/dehydrated.conf"
LOCK_FILE="${ACME_DIR}/.lock"
ACME_RESULTS_FILE="${ACME_DIR}/.run_results.txt"

# Carrega .env se existir (sobrescreve variáveis definidas acima)
# shellcheck source=/dev/null
[[ -f "${ACME_DIR}/.env" ]] && source "${ACME_DIR}/.env"

# Se ACME_EMAIL foi definido no .env, usa ele
CONTACT_EMAIL="${ACME_EMAIL:-${CONTACT_EMAIL}}"

# Notificações Rocket.Chat (opcional — configure via .env ou variáveis de ambiente)
#   ROCKETCHAT_WEBHOOK_URL — URL do incoming webhook (vazio = notificações desligadas)
#   ROCKETCHAT_CHANNEL     — canal/usuário de destino (opcional, usa o padrão do webhook se vazio)
#   ROCKETCHAT_USERNAME    — nome exibido para as mensagens
ROCKETCHAT_WEBHOOK_URL="${ROCKETCHAT_WEBHOOK_URL:-}"
ROCKETCHAT_CHANNEL="${ROCKETCHAT_CHANNEL:-}"
ROCKETCHAT_USERNAME="${ROCKETCHAT_USERNAME:-bigip-acme}"

# =============================================================================
# FUNÇÕES AUXILIARES
# =============================================================================

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
die() { log "ERRO: $*" >&2; exit 1; }
tmsh_cmd() { "${TMSH}" "$@" 2>&1; }

# =============================================================================
# Notificação Rocket.Chat via incoming webhook (silenciosa se não configurada)
# Mesma implementação usada em bigip-hook.sh — usada aqui só para o resumo final.
# =============================================================================
json_escape() {
    local s="${1}"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    printf '%s' "${s}"
}

notify_rocketchat() {
    local message="${1}"
    local color="${2:-good}"

    [[ -z "${ROCKETCHAT_WEBHOOK_URL}" ]] && return 0

    local esc_msg esc_user channel_field=""
    esc_msg=$(json_escape "${message}")
    esc_user=$(json_escape "${ROCKETCHAT_USERNAME}")
    if [[ -n "${ROCKETCHAT_CHANNEL}" ]]; then
        channel_field="\"channel\":\"$(json_escape "${ROCKETCHAT_CHANNEL}")\","
    fi

    local payload="{\"username\":\"${esc_user}\",${channel_field}\"attachments\":[{\"text\":\"${esc_msg}\",\"color\":\"${color}\"}]}"

    curl -fsS -m 10 -X POST -H "Content-Type: application/json" \
        -d "${payload}" "${ROCKETCHAT_WEBHOOK_URL}" >/dev/null 2>&1 \
        || log "AVISO: falha ao enviar notificação para o Rocket.Chat."
}

# Lê o ACME_RESULTS_FILE (preenchido pelo bigip-hook.sh a cada domínio processado)
# e envia um resumo único da execução para o Rocket.Chat.
send_run_summary() {
    [[ -f "${ACME_RESULTS_FILE}" ]] || return 0
    [[ -z "${ROCKETCHAT_WEBHOOK_URL}" ]] && return 0

    local total=0 ok=0 err=0
    local -a lines=()
    while IFS='|' read -r status event domain detail; do
        [[ -z "${status}" ]] && continue
        total=$((total + 1))
        if [[ "${status}" == "OK" ]]; then
            ok=$((ok + 1))
        else
            err=$((err + 1))
        fi
        lines+=("${status} [${event}] ${domain}: ${detail}")
    done < "${ACME_RESULTS_FILE}"

    [[ ${total} -eq 0 ]] && return 0

    local color="good"
    [[ ${err} -gt 0 ]] && color="danger"

    local summary
    summary=$(printf '*Resumo da renovação ACME* — %s\nOK: %d | Erros: %d | Total: %d\n\n%s' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "${ok}" "${err}" "${total}" \
        "$(printf '%s\n' "${lines[@]}")")

    notify_rocketchat "${summary}" "${color}"
}

check_deps() {
    for cmd in curl openssl bash awk; do
        command -v "$cmd" &>/dev/null || die "Dependência não encontrada: $cmd"
    done
}

acquire_lock() {
    if [[ -f "${LOCK_FILE}" ]]; then
        local pid
        pid=$(cat "${LOCK_FILE}" 2>/dev/null || echo "")
        if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
            die "Outra instância em execução (PID ${pid})."
        fi
        rm -f "${LOCK_FILE}"
    fi
    echo $$ > "${LOCK_FILE}"
    trap 'rm -f "${LOCK_FILE}"; exit' INT TERM EXIT
}

# Deriva o nome do Data Group a partir do nome do VS HTTPS.
# /Common/vs_site_a_https  →  acme_vs_site_a_https
sanitize_vs_name() {
    local vs="${1}"
    vs="${vs##*/}"       # remove partição (/Common/, /Tenant/, etc.)
    vs="${vs//./_}"      # ponto → underscore
    echo "${OBJECT_PREFIX}_${vs}" | tr -cd '[:alnum:]_-' | cut -c1-63
}

# =============================================================================
# SETUP — Data Group de challenge HTTP-01
# =============================================================================

setup_challenge_datagroup() {
    log "Configurando Data Group de challenge '${DATAGROUP_NAME}'..."
    if "${TMSH}" list ltm data-group internal "/${PARTITION}/${DATAGROUP_NAME}" &>/dev/null 2>&1; then
        log "  já existe."
    else
        tmsh_cmd create ltm data-group internal "/${PARTITION}/${DATAGROUP_NAME}" type string
        log "  criado."
    fi
}

# =============================================================================
# SETUP — iRule para responder o challenge
# =============================================================================

setup_irule() {
    log "Configurando iRule '${IRULE_NAME}'..."
    if "${TMSH}" list ltm rule "/${PARTITION}/${IRULE_NAME}" &>/dev/null 2>&1; then
        log "  já existe."
        return
    fi

    local tmp_conf
    tmp_conf=$(mktemp /var/tmp/acme_irule_XXXXXX.conf)
    cat > "${tmp_conf}" <<EOF
ltm rule /${PARTITION}/${IRULE_NAME} {
when HTTP_REQUEST {
    if { [HTTP::path] starts_with "/.well-known/acme-challenge/" } {
        set token [string range [HTTP::path] 28 end]
        if { [class exists ${DATAGROUP_NAME}] } {
            set response [class lookup \$token ${DATAGROUP_NAME}]
            if { \$response ne "" } {
                HTTP::respond 200 content \$response "Content-Type" "text/plain"
                return
            }
        }
    }
}
}
EOF
    tmsh_cmd load sys config merge file "${tmp_conf}"
    rm -f "${tmp_conf}"
    log "  criada."
}

# =============================================================================
# SETUP — associar iRule ao VS HTTP
# =============================================================================

attach_irule_to_vs() {
    local vs="${1}"
    local new_irule="/${PARTITION}/${IRULE_NAME}"

    if ! "${TMSH}" list ltm virtual "${vs}" &>/dev/null 2>&1; then
        log "AVISO: VS HTTP '${vs}' não encontrado. Ignorando."
        return
    fi

    local rules_output
    rules_output=$("${TMSH}" list ltm virtual "${vs}" rules 2>/dev/null || echo "")

    if echo "${rules_output}" | grep -qF "${new_irule}"; then
        log "  iRule já está em '${vs}'."
        return
    fi

    local existing_rules
    existing_rules=$(echo "${rules_output}" | \
        awk '/rules \{/{f=1;next} f && /^\s*\}/{exit} f{gsub(/^[[:space:]]+/,""); print $1}' | \
        tr '\n' ' ')

    "${TMSH}" -c "modify ltm virtual ${vs} rules { ${existing_rules}${new_irule} }"
    log "  iRule adicionada ao VS HTTP '${vs}'."
}

setup_vs_irule() {
    local -a vs_list=()

    if [[ ${#ARG_VS_LIST[@]} -gt 0 ]]; then
        vs_list=("${ARG_VS_LIST[@]}")
    elif [[ -n "${ACME_VS_NAME}" ]]; then
        read -ra vs_list <<< "${ACME_VS_NAME}"
    fi

    if [[ ${#vs_list[@]} -eq 0 ]]; then
        if [[ -z "${ACME_VS_DESTINATION}" ]]; then
            log "AVISO: nenhum VS HTTP configurado. Adicione a iRule '${IRULE_NAME}' manualmente."
            return
        fi
        local vs_name="/${PARTITION}/${OBJECT_PREFIX}_challenge_vs"
        if ! "${TMSH}" list ltm virtual "${vs_name}" &>/dev/null 2>&1; then
            log "Criando VS HTTP dedicado: ${vs_name}"
            tmsh_cmd create ltm virtual "${vs_name}" \
                destination "${ACME_VS_DESTINATION}" \
                ip-protocol tcp \
                profiles add { http } \
                rules { "/${PARTITION}/${IRULE_NAME}" }
        fi
    else
        for vs in "${vs_list[@]}"; do
            attach_irule_to_vs "${vs}"
        done
    fi
    tmsh_cmd save sys config
}

# =============================================================================
# SETUP — Data Group por VS HTTPS (mapeia domínios → VS HTTPS)
# =============================================================================

setup_domain_dg() {
    local https_vs="${1}"
    local dg_name
    dg_name=$(sanitize_vs_name "${https_vs}")
    local full_dg="/${PARTITION}/${dg_name}"

    log "Configurando Data Group de domínios '${dg_name}' → VS '${https_vs}'..."

    if "${TMSH}" list ltm data-group internal "${full_dg}" &>/dev/null 2>&1; then
        log "  já existe."
        # Garante que o registro _vs_https está correto
        "${TMSH}" -c "modify ltm data-group internal ${full_dg} records add { _vs_https { data ${https_vs} } }" 2>/dev/null || true
        return
    fi

    tmsh_cmd create ltm data-group internal "${full_dg}" type string
    "${TMSH}" -c "modify ltm data-group internal ${full_dg} records add { _vs_https { data ${https_vs} } }"
    tmsh_cmd save sys config

    log "  Data Group '${dg_name}' criado."
    log ""
    log "  Adicione domínios com tmsh:"
    log "    tmsh modify ltm data-group internal ${full_dg} \\"
    log "        records add { \"dominio.com.br\" { data \"\" } }"
    log ""
    log "  Para SANs (múltiplos domínios no mesmo cert), separe por espaço na chave:"
    log "    tmsh modify ltm data-group internal ${full_dg} \\"
    log "        records add { \"dominio.com.br www.dominio.com.br\" { data \"\" } }"
}

# =============================================================================
# SETUP — orquestrador
# =============================================================================

cmd_setup() {
    log "=== Iniciando setup do bigip-acme ==="

    if [[ -z "${CONTACT_EMAIL}" ]] || [[ "${CONTACT_EMAIL}" == *"example.com"* ]]; then
        die "Configure CONTACT_EMAIL com um e-mail válido em bigip-acme.sh."
    fi

    check_deps

    mkdir -p "${ACME_DIR}" "${CERTS_DIR}" "${LOG_DIR}" "${ACME_DIR}/wellknown"
    chmod 700 "${ACME_DIR}"

    # Baixar dehydrated
    if [[ ! -x "${DEHYDRATED}" ]]; then
        log "Baixando dehydrated..."
        curl -fsSL "${DEHYDRATED_URL}" -o "${DEHYDRATED}"
        chmod +x "${DEHYDRATED}"
    else
        log "dehydrated já existe."
    fi

    # Gerar dehydrated.conf
    cat > "${DEHYDRATED_CONF}" <<EOF
CA="${CA}"
CONTACT_EMAIL="${CONTACT_EMAIL}"
BASEDIR="${ACME_DIR}"
CERTDIR="${CERTS_DIR}"
ACCOUNTDIR="${ACME_DIR}/accounts"
HOOK="${HOOK_SCRIPT}"
HOOK_CHAIN="no"
CHALLENGETYPE="http-01"
WELLKNOWN="${ACME_DIR}/wellknown"
KEYSIZE="4096"
KEY_ALGO="rsa"
RENEW_DAYS="30"
LOCKFILE="${LOCK_FILE}.dehydrated"
EOF
    chmod 600 "${DEHYDRATED_CONF}"
    log "dehydrated.conf atualizado."

    # Verificar hook
    local hook_src
    hook_src="$(dirname "$(readlink -f "$0")")/bigip-hook.sh"
    if [[ ! -f "${HOOK_SCRIPT}" ]] && [[ -f "${hook_src}" ]]; then
        cp "${hook_src}" "${HOOK_SCRIPT}"
        chmod +x "${HOOK_SCRIPT}"
        log "Hook copiado para ${HOOK_SCRIPT}"
    elif [[ ! -f "${HOOK_SCRIPT}" ]]; then
        die "bigip-hook.sh não encontrado em ${ACME_DIR}/. Copie-o antes de continuar."
    fi

    setup_challenge_datagroup
    setup_irule

    log "Registrando conta ACME..."
    "${DEHYDRATED}" --config "${DEHYDRATED_CONF}" --register --accept-terms || true

    setup_vs_irule

    # Criar Data Group por VS HTTPS informado via --vs-https
    for vs in "${ARG_HTTPS_VS_LIST[@]+"${ARG_HTTPS_VS_LIST[@]}"}"; do
        setup_domain_dg "${vs}"
    done

    log ""
    log "=== Setup concluído! ==="
    log "Próximos passos:"
    log "  1. Adicione domínios aos Data Groups (veja instruções acima)"
    log "  2. Execute: ${0} para emitir os certificados"
    log "  3. Cron: 0 3 * * 1 ${0} >> ${LOG_DIR}/acme.log 2>&1"
}

# =============================================================================
# SETUP-WATCH — cria iCall handler que monitora mudanças nos Data Groups
# =============================================================================

cmd_setup_watch() {
    log "=== Configurando iCall watch handler ==="

    local watch_script="${ACME_DIR}/bigip-acme-watch.sh"

    # Copiar watcher se não existir no destino
    local watch_src
    watch_src="$(dirname "$(readlink -f "$0")")/bigip-acme-watch.sh"
    if [[ ! -f "${watch_script}" ]] && [[ -f "${watch_src}" ]]; then
        cp "${watch_src}" "${watch_script}"
    elif [[ ! -f "${watch_script}" ]]; then
        die "bigip-acme-watch.sh não encontrado. Copie-o para ${ACME_DIR}/."
    fi
    chmod +x "${watch_script}"

    # Criar iCall script (Tcl que chama o watcher bash)
    local icall_script_name="${OBJECT_PREFIX}_dg_watcher"
    local icall_handler_name="${OBJECT_PREFIX}_dg_watch_handler"

    if "${TMSH}" list sys icall script "${icall_script_name}" &>/dev/null 2>&1; then
        log "iCall script '${icall_script_name}' já existe. Atualizando..."
        tmsh_cmd delete sys icall script "${icall_script_name}"
    fi

    # Cria o script iCall via arquivo conf (mesmo padrão da iRule)
    local tmp_conf
    tmp_conf=$(mktemp /var/tmp/acme_icall_XXXXXX.conf)
    cat > "${tmp_conf}" <<EOF
sys icall script ${icall_script_name} {
    definition {
        catch {
            exec /bin/bash ${watch_script}
        }
    }
}
EOF
    tmsh_cmd load sys config merge file "${tmp_conf}"
    rm -f "${tmp_conf}"
    log "iCall script '${icall_script_name}' criado."

    # Criar iCall periodic handler (intervalo em segundos — padrão: 60s)
    local interval="${WATCH_INTERVAL:-60}"

    if "${TMSH}" list sys icall handler periodic "${icall_handler_name}" &>/dev/null 2>&1; then
        log "iCall handler '${icall_handler_name}' já existe. Atualizando..."
        tmsh_cmd delete sys icall handler periodic "${icall_handler_name}"
    fi

    local tmp_conf2
    tmp_conf2=$(mktemp /var/tmp/acme_icall_h_XXXXXX.conf)
    cat > "${tmp_conf2}" <<EOF
sys icall handler periodic ${icall_handler_name} {
    interval ${interval}
    script ${icall_script_name}
}
EOF
    tmsh_cmd load sys config merge file "${tmp_conf2}"
    rm -f "${tmp_conf2}"

    tmsh_cmd save sys config

    log "iCall handler '${icall_handler_name}' criado (intervalo: ${interval}s)."
    log ""
    log "A partir de agora, qualquer alteração nos Data Groups acme_* dispara"
    log "a renovação automaticamente em até ${interval} segundos."
    log ""
    log "Para remover o watch:"
    log "  tmsh delete sys icall handler periodic ${icall_handler_name}"
    log "  tmsh delete sys icall script ${icall_script_name}"
    log "  tmsh save sys config"
}

# =============================================================================
# LIMPEZA — remove objetos BIG-IP de domínios removidos do Data Group
# =============================================================================

# Mesma lógica do sanitize_name() do hook (pontos → underscore, etc.)
sanitize_domain_name() {
    local domain="${1}"
    domain="${domain//\*/wildcard}"
    domain="${domain//./_}"
    echo "${domain}" | tr -cd '[:alnum:]_-' | cut -c1-63
}

# Remove perfil SSL, certificado, chave e chain de um domínio
cleanup_domain() {
    local domain="${1}"   # domínio primário (primeiro token da linha do DG)
    local https_vs="${2}" # VS HTTPS associado ao DG

    local cert_name="${OBJECT_PREFIX}_$(sanitize_domain_name "${domain}")"
    local ssl_profile="/${PARTITION}/${cert_name}_ssl"
    local cert_obj="/${PARTITION}/${cert_name}.crt"
    local key_obj="/${PARTITION}/${cert_name}.key"
    local chain_obj="/${PARTITION}/${cert_name}-chain.crt"

    log "  Limpando objetos do domínio '${domain}'..."

    # 1. Desassociar perfil SSL do VS HTTPS (incondicional — ignora erro se já não estava lá)
    if [[ -n "${https_vs}" ]] && "${TMSH}" list ltm virtual "${https_vs}" &>/dev/null 2>&1; then
        log "    Removendo perfil '${ssl_profile}' do VS '${https_vs}'..."
        "${TMSH}" -c "modify ltm virtual ${https_vs} profiles delete { ${ssl_profile} }" 2>/dev/null || true
    fi

    # 2. Deletar perfil SSL client
    if "${TMSH}" list ltm profile client-ssl "${ssl_profile}" &>/dev/null 2>&1; then
        log "    Deletando perfil SSL '${ssl_profile}'..."
        tmsh_cmd delete ltm profile client-ssl "${ssl_profile}" || \
            log "    AVISO: erro ao deletar perfil SSL."
    fi

    # 3. Deletar certificado leaf
    if "${TMSH}" list sys crypto cert "${cert_obj}" &>/dev/null 2>&1; then
        log "    Deletando certificado '${cert_obj}'..."
        tmsh_cmd delete sys crypto cert "${cert_obj}" || \
            log "    AVISO: erro ao deletar certificado."
    fi

    # 4. Deletar chave privada
    if "${TMSH}" list sys crypto key "${key_obj}" &>/dev/null 2>&1; then
        log "    Deletando chave '${key_obj}'..."
        tmsh_cmd delete sys crypto key "${key_obj}" || \
            log "    AVISO: erro ao deletar chave."
    fi

    # 5. Deletar chain (opcional — pode não existir)
    if "${TMSH}" list sys crypto cert "${chain_obj}" &>/dev/null 2>&1; then
        log "    Deletando chain '${chain_obj}'..."
        tmsh_cmd delete sys crypto cert "${chain_obj}" || \
            log "    AVISO: erro ao deletar chain."
    fi

    # 6. Remover certs locais do dehydrated
    local dehydrated_cert_dir="${CERTS_DIR}/${domain}"
    if [[ -d "${dehydrated_cert_dir}" ]]; then
        log "    Removendo certs locais em '${dehydrated_cert_dir}'..."
        rm -rf "${dehydrated_cert_dir}"
    fi

    log "  Limpeza de '${domain}' concluída."
}

# Compara domínios actuais do DG com o estado anterior e limpa os removidos.
# Estado guardado em: /shared/acme/.state_<dg_basename>.txt
cleanup_removed_domains() {
    local dg="${1}"
    local https_vs="${2}"
    local current_domains_file="${3}"

    local dg_basename="${dg##*/}"
    local state_file="${ACME_DIR}/.state_${dg_basename}.txt"

    if [[ ! -f "${state_file}" ]]; then
        # Primeira execução — apenas regista o estado inicial, nada a limpar
        cp "${current_domains_file}" "${state_file}" 2>/dev/null || true
        return 0
    fi

    local removed
    removed=$(comm -23 \
        <(sort "${state_file}") \
        <(sort "${current_domains_file}") \
    ) || true

    if [[ -z "${removed}" ]]; then
        return 0
    fi

    log "  Domínios removidos do Data Group '${dg_basename}' — limpando objetos BIG-IP..."
    local needs_save=false
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        local primary_domain
        primary_domain=$(echo "${line}" | awk '{print $1}')
        log "    - ${line}"
        cleanup_domain "${primary_domain}" "${https_vs}"
        needs_save=true
    done <<< "${removed}"

    ${needs_save} && tmsh_cmd save sys config
}

# =============================================================================
# RENOVAÇÃO — descobre DGs automaticamente, processa um por VS HTTPS
# =============================================================================

# Lê o valor de um registro específico de um Data Group
dg_get_record() {
    local dg="${1}" key="${2}"
    "${TMSH}" list ltm data-group internal "${dg}" 2>/dev/null | \
        awk -v k="${key}" '
            $0 ~ k" {" { found=1; next }
            found && /data / {
                val=$2; gsub(/"/, "", val); print val; found=0
            }
        '
}

# Extrai linhas de domínios de um Data Group (ignora registros com prefixo _)
# Suporta dois formatos de saída do tmsh:
#   Multi-linha (registro com valor): "key {\n    data value\n}"
#   Compacto (valor vazio):           "key { }"
dg_get_domains() {
    local dg="${1}"
    "${TMSH}" list ltm data-group internal "${dg}" 2>/dev/null | \
        awk '
            /records \{/          { in_r=1; next }
            in_r && /^    \}[[:space:]]*$/ { in_r=0; next }
            in_r && /\{/ {
                k=$0
                gsub(/^[[:space:]]+/, "", k)   # remove indentação
                gsub(/ \{.*/, "", k)            # remove " {" e tudo depois (cobre ambos os formatos)
                gsub(/^"/, "", k)              # remove aspas iniciais
                gsub(/"$/, "", k)              # remove aspas finais
                if (k != "" && k != "records" && k !~ /^_/) print k
            }
        '
}

process_domain_dg() {
    local dg="${1}"

    local https_vs
    https_vs=$(dg_get_record "${dg}" "_vs_https")

    if [[ -z "${https_vs}" ]]; then
        log "AVISO: '${dg}' sem registro '_vs_https'. Ignorando."
        return
    fi

    local tmp_domains
    tmp_domains=$(mktemp /var/tmp/acme_domains_XXXXXX.txt)
    dg_get_domains "${dg}" > "${tmp_domains}"

    local domain_count=0
    domain_count=$(grep -c '.' "${tmp_domains}" 2>/dev/null) || domain_count=0

    # Detectar domínios removidos do DG e limpar seus objetos no BIG-IP
    cleanup_removed_domains "${dg}" "${https_vs}" "${tmp_domains}"

    # Atualizar arquivo de estado com a lista actual de domínios
    local dg_basename="${dg##*/}"
    cp "${tmp_domains}" "${ACME_DIR}/.state_${dg_basename}.txt" 2>/dev/null || true

    if [[ "${domain_count}" -eq 0 ]]; then
        log "Data Group '${dg}': nenhum domínio configurado. Ignorando."
        rm -f "${tmp_domains}"
        return
    fi

    log "--- Processando '${dg}' → VS HTTPS: ${https_vs} (${domain_count} linha(s)) ---"

    export BIGIP_HTTPS_VS="${https_vs}"
    "${DEHYDRATED}" \
        --config "${DEHYDRATED_CONF}" \
        --cron \
        --domains-txt "${tmp_domains}" \
        --hook "${HOOK_SCRIPT}" \
        --no-lock

    rm -f "${tmp_domains}"
}

cmd_renew() {
    log "=== Iniciando renovação de certificados ACME ==="
    check_deps
    acquire_lock

    : > "${ACME_RESULTS_FILE}"
    export ACME_RESULTS_FILE
    export BIGIP_ACME_DIR="${ACME_DIR}"
    export ROCKETCHAT_WEBHOOK_URL ROCKETCHAT_CHANNEL ROCKETCHAT_USERNAME

    [[ -x "${DEHYDRATED}" ]] || die "dehydrated não encontrado. Execute: ${0} --setup"

    # Registrar conta se necessário
    if ! "${DEHYDRATED}" --config "${DEHYDRATED_CONF}" --account 2>/dev/null | grep -q 'account'; then
        log "Registrando conta ACME..."
        "${DEHYDRATED}" --config "${DEHYDRATED_CONF}" --register --accept-terms || \
            die "Falha ao registrar conta ACME. Verifique CONTACT_EMAIL."
    fi

    # Descobrir todos os Data Groups de domínios: acme_* exceto acme_challenges
    # Usa awk em vez de grep -oP (BIG-IP não tem suporte a Perl regex no grep)
    local -a domain_dgs=()
    while IFS= read -r dg; do
        [[ -n "${dg}" ]] && domain_dgs+=("${dg}")
    done < <(
        "${TMSH}" list ltm data-group internal 2>/dev/null | \
        awk -v part="${PARTITION}" -v prefix="${OBJECT_PREFIX}_" -v skip="${DATAGROUP_NAME}" '
            /^ltm data-group internal/ {
                name = $4
                # Remove barra final se houver
                sub(/\/$/, "", name)
                # Extrai só o nome sem a partição para comparar com o prefixo
                n = name; sub("^/" part "/", "", n)
                if (n ~ ("^" prefix) && n != skip) print name
            }
        '
    )

    if [[ ${#domain_dgs[@]} -eq 0 ]]; then
        log "Nenhum Data Group de domínios encontrado (padrão: /${PARTITION}/${OBJECT_PREFIX}_*)."
        log "Crie um com: ${0} --setup --vs-https /Common/<vs_https>"
        exit 0
    fi

    log "Encontrados ${#domain_dgs[@]} Data Group(s): ${domain_dgs[*]}"

    # Exportar variáveis fixas para o hook
    export BIGIP_PARTITION="${PARTITION}"
    export BIGIP_DATAGROUP="${DATAGROUP_NAME}"
    export BIGIP_OBJECT_PREFIX="${OBJECT_PREFIX}"

    for dg in "${domain_dgs[@]}"; do
        process_domain_dg "${dg}"
    done

    log "=== Renovação concluída ==="
    send_run_summary
}

# =============================================================================
# ENTRY POINT
# =============================================================================

usage() {
    sed -n '/^# Uso:/,/^# =====/{ /^# =====/d; s/^# \{0,1\}//; p }' "$0"
    exit 0
}

main() {
    local cmd="renew"
    ARG_VS_LIST=()
    ARG_HTTPS_VS_LIST=()

    while [[ $# -gt 0 ]]; do
        case "${1}" in
            --setup)        cmd="setup"; shift ;;
            --setup-watch)  cmd="setup-watch"; shift ;;
            --vs)           [[ -z "${2:-}" ]] && die "--vs requer argumento"; ARG_VS_LIST+=("${2}"); shift 2 ;;
            --vs=*)         ARG_VS_LIST+=("${1#--vs=}"); shift ;;
            --vs-https)     [[ -z "${2:-}" ]] && die "--vs-https requer argumento"; ARG_HTTPS_VS_LIST+=("${2}"); shift 2 ;;
            --vs-https=*)   ARG_HTTPS_VS_LIST+=("${1#--vs-https=}"); shift ;;
            --dest)         [[ -z "${2:-}" ]] && die "--dest requer argumento"; ACME_VS_DESTINATION="${2}"; shift 2 ;;
            --dest=*)       ACME_VS_DESTINATION="${1#--dest=}"; shift ;;
            --staging)      CA="https://acme-staging-v02.api.letsencrypt.org/directory"; log "Modo staging."; shift ;;
            --help|-h)      usage ;;
            *)              die "Argumento desconhecido: '${1}'. Use --help." ;;
        esac
    done

    case "${cmd}" in
        setup)       cmd_setup ;;
        setup-watch) cmd_setup_watch ;;
        renew)       cmd_renew ;;
    esac
}

main "$@"
