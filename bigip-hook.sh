#!/bin/bash
# =============================================================================
# bigip-hook.sh — Hook do dehydrated para F5 BIG-IP
#
# Callbacks implementados:
#   deploy_challenge   — adiciona token no Data Group para o iRule servir
#   clean_challenge    — remove o token do Data Group após validação
#   deploy_cert        — instala cert/key/chain via tmsh e atualiza perfil SSL
#   unchanged_cert     — log de que o cert ainda é válido (com checagem de drift)
#   startup / exit_hook — reservados para log
#
# Variáveis esperadas do bigip-acme.sh:
#   BIGIP_PARTITION     — ex: "Common"
#   BIGIP_DATAGROUP     — ex: "acme_challenges"
#   BIGIP_OBJECT_PREFIX — ex: "acme"
#   BIGIP_ACME_DIR      — ex: "/shared/acme"
#   ACME_RESULTS_FILE   — arquivo onde cada domínio processado registra seu resultado
#   ROCKETCHAT_WEBHOOK_URL / ROCKETCHAT_CHANNEL / ROCKETCHAT_USERNAME — notificações
# =============================================================================

set -euo pipefail

TMSH="/usr/bin/tmsh"
PARTITION="${BIGIP_PARTITION:-Common}"
DATAGROUP="${BIGIP_DATAGROUP:-acme_challenges}"
OBJECT_PREFIX="${BIGIP_OBJECT_PREFIX:-acme}"
ACME_DIR="${BIGIP_ACME_DIR:-/shared/acme}"
RESULTS_FILE="${ACME_RESULTS_FILE:-${ACME_DIR}/.run_results.txt}"

ROCKETCHAT_WEBHOOK_URL="${ROCKETCHAT_WEBHOOK_URL:-}"
ROCKETCHAT_CHANNEL="${ROCKETCHAT_CHANNEL:-}"
ROCKETCHAT_USERNAME="${ROCKETCHAT_USERNAME:-bigip-acme}"

CURRENT_DOMAIN=""
CURRENT_HOOK=""
NOTIFIED_ERROR=false

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [hook] $*"
}

tmsh_cmd() {
    "${TMSH}" "$@"
}

# =============================================================================
# Registro do resultado de cada domínio processado, para o resumo final
# (lido por bigip-acme.sh no fim da execução) — formato: STATUS|EVENTO|DOMINIO|DETALHE
# =============================================================================
record_result() {
    local status="${1}" event="${2}" domain="${3}" detail="${4:-}"
    echo "${status}|${event}|${domain}|${detail//$'\n'/ }" >> "${RESULTS_FILE}"
}

# =============================================================================
# Notificação Rocket.Chat via incoming webhook (silenciosa se não configurada)
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

# =============================================================================
# Handler de erro — dispara para qualquer falha não tratada explicitamente
# (set -e aciona isso antes de o script sair com código != 0)
# =============================================================================
on_error() {
    local exit_code=$? line_no="${1}" cmd="${2}"

    if ${NOTIFIED_ERROR}; then
        NOTIFIED_ERROR=false
        return
    fi

    log "ERRO: falha na linha ${line_no} (comando: ${cmd}) durante hook '${CURRENT_HOOK}' domínio '${CURRENT_DOMAIN}'."
    record_result "ERROR" "${CURRENT_HOOK:-desconhecido}" "${CURRENT_DOMAIN:-desconhecido}" "${cmd} (exit ${exit_code})"
    notify_rocketchat "❌ *bigip-acme*: falha ao processar *${CURRENT_DOMAIN:-desconhecido}* (hook: ${CURRENT_HOOK}).
Comando: \`${cmd}\`
Exit: ${exit_code}" "danger"
}
trap 'on_error "${LINENO}" "${BASH_COMMAND}"' ERR

# =============================================================================
# Sanitiza o nome do domínio para uso como nome de objeto no BIG-IP
# BIG-IP aceita letras, números, hífen, ponto e underscore (max 63 chars)
# =============================================================================
sanitize_name() {
    local domain="${1}"
    # Substitui * (wildcard) por "wildcard"
    domain="${domain//\*/wildcard}"
    # Substitui pontos por underscore — BIG-IP usa o ponto como separador de extensão
    # (ex: "nome.key", "nome.crt"), então pontos no nome causam ambiguidade
    domain="${domain//./_}"
    # Remove qualquer outro caractere inválido
    echo "${domain}" | tr -cd '[:alnum:]_-' | cut -c1-63
}

# =============================================================================
# Marcador do último deploy confirmado com sucesso para o domínio (fingerprint
# do cert local no momento do deploy). Usado por unchanged_cert() para detectar
# quando o dehydrated acha que está tudo atualizado mas o BIG-IP não recebeu o
# último certificado (ex.: deploy anterior falhou depois do cert já emitido).
# =============================================================================
deploy_marker_file() {
    local domain="${1}"
    echo "${ACME_DIR}/.deployed_$(sanitize_name "${domain}").sha256"
}

cert_deploy_drifted() {
    local domain="${1}" certfile="${2}"
    local marker current_hash last_hash
    marker=$(deploy_marker_file "${domain}")
    [[ -f "${marker}" ]] || return 0

    current_hash=$(openssl x509 -noout -fingerprint -sha256 -in "${certfile}" 2>/dev/null || echo "")
    last_hash=$(cat "${marker}" 2>/dev/null || echo "")
    [[ -z "${current_hash}" ]] && return 1
    [[ "${current_hash}" != "${last_hash}" ]]
}

mark_deploy_success() {
    local domain="${1}" certfile="${2}"
    openssl x509 -noout -fingerprint -sha256 -in "${certfile}" 2>/dev/null > "$(deploy_marker_file "${domain}")" || true
}

# =============================================================================
# deploy_challenge DOMAIN TOKEN_FILENAME KEY_AUTH
#   Chamado para cada domínio antes da verificação ACME.
#   Insere o token no Data Group para que a iRule responda ao challenge.
# =============================================================================
deploy_challenge() {
    local domain="${1}"
    local token_file="${2}"
    local key_auth="${3}"

    CURRENT_DOMAIN="${domain}"
    CURRENT_HOOK="deploy_challenge"

    log "deploy_challenge: domínio=${domain} token=${token_file}"

    # Adiciona ou atualiza o registro no Data Group
    # Se o Data Group já tiver o token, o modify records add é idempotente
    tmsh_cmd modify ltm data-group internal \
        "/${PARTITION}/${DATAGROUP}" \
        records add { "${token_file}" { data "${key_auth}" } } 2>&1 | \
        grep -v "^$" || true

    # Pequena pausa para garantir propagação no plano de dados
    sleep 2
    log "deploy_challenge: token '${token_file}' inserido no Data Group."
}

# =============================================================================
# clean_challenge DOMAIN TOKEN_FILENAME KEY_AUTH
#   Chamado após a verificação (sucesso ou falha).
#   Remove o token do Data Group.
# =============================================================================
clean_challenge() {
    local domain="${1}"
    local token_file="${2}"
    local key_auth="${3}"

    CURRENT_DOMAIN="${domain}"
    CURRENT_HOOK="clean_challenge"

    log "clean_challenge: removendo token '${token_file}' do Data Group..."

    tmsh_cmd modify ltm data-group internal \
        "/${PARTITION}/${DATAGROUP}" \
        records delete { "${token_file}" } 2>&1 | \
        grep -v "^$" || true

    log "clean_challenge: token removido."
}

# =============================================================================
# deploy_cert DOMAIN KEYFILE CERTFILE FULLCHAINFILE CHAINFILE TIMESTAMP [EVENTO]
#   Chamado após emissão/renovação bem-sucedida (ou por unchanged_cert, quando
#   detecta que o BIG-IP está fora de sincronia com o cert local).
#
#   Instala o certificado no BIG-IP sob um nome de objeto ÚNICO por versão
#   (sufixo = timestamp) em vez de sobrescrever o objeto fixo em uso pelo
#   profile — sobrescrever um key/cert vinculado a um profile ativo é o que
#   causava o erro "key and certificate do not match" (BIG-IP não garante que
#   o overwrite in-place seja aplicado de forma consistente nos dois objetos).
#   Depois do cutover do profile confirmado, a versão anterior é removida.
# =============================================================================
deploy_cert() {
    local domain="${1}"
    local keyfile="${2}"
    local certfile="${3}"
    local fullchainfile="${4}"
    local chainfile="${5}"
    local timestamp="${6:-$(date +%s)}"
    local event="${7:-deploy_cert}"

    CURRENT_DOMAIN="${domain}"
    CURRENT_HOOK="${event}"

    local cert_name
    cert_name="${OBJECT_PREFIX}_$(sanitize_name "${domain}")"
    local bigip_cert="/${PARTITION}/${cert_name}"
    local ssl_profile="${bigip_cert}_ssl"

    # Nomes de objeto versionados — nunca reaproveita um nome já em uso
    local key_obj="${bigip_cert}-${timestamp}.key"
    local cert_obj="${bigip_cert}-${timestamp}.crt"
    local chain_obj="${bigip_cert}-${timestamp}-chain.crt"

    log "deploy_cert: instalando certificado para '${domain}' como '${cert_name}' (versão ${timestamp})"

    # Sanidade: confirma que a chave e o certificado emitidos combinam entre
    # si ANTES de mexer no BIG-IP (isola bug do dehydrated de bug do BIG-IP)
    local mod_key mod_cert
    mod_key=$(openssl rsa -noout -modulus -in "${keyfile}" 2>/dev/null | openssl md5)
    mod_cert=$(openssl x509 -noout -modulus -in "${certfile}" 2>/dev/null | openssl md5)
    if [[ -z "${mod_key}" ]] || [[ "${mod_key}" != "${mod_cert}" ]]; then
        log "ERRO: chave e certificado de '${domain}' não combinam entre si. Abortando antes do BIG-IP."
        record_result "ERROR" "${event}" "${domain}" "key/cert do dehydrated não combinam (antes de tocar no BIG-IP)"
        NOTIFIED_ERROR=true
        notify_rocketchat "❌ *bigip-acme*: chave/certificado emitidos para *${domain}* não combinam entre si. Deploy abortado sem alterar o BIG-IP." "danger"
        return 1
    fi

    log "  Instalando chave privada (${key_obj})..."
    tmsh_cmd install sys crypto key "${key_obj}" from-local-file "${keyfile}"

    log "  Instalando certificado (${cert_obj})..."
    tmsh_cmd install sys crypto cert "${cert_obj}" from-local-file "${certfile}"

    local has_chain=false
    if [[ -f "${chainfile}" ]] && [[ -s "${chainfile}" ]]; then
        log "  Instalando chain (${chain_obj})..."
        tmsh_cmd install sys crypto cert "${chain_obj}" from-local-file "${chainfile}"
        has_chain=true
    fi

    # Guarda os objetos da versão anterior (se houver) para limpeza após o cutover
    local profile_dump old_cert old_key old_chain
    profile_dump=$("${TMSH}" list ltm profile client-ssl "${ssl_profile}" 2>/dev/null || true)
    old_cert=$(printf '%s\n' "${profile_dump}" | awk '$1=="cert"{print $2}')
    old_key=$(printf '%s\n' "${profile_dump}" | awk '$1=="key"{print $2}')
    old_chain=$(printf '%s\n' "${profile_dump}" | awk '$1=="chain"{print $2}')

    local chain_arg=""
    ${has_chain} && chain_arg="chain ${chain_obj}"

    if [[ -n "${profile_dump}" ]]; then
        log "  Atualizando perfil SSL client '${cert_name}_ssl' → versão ${timestamp}..."
        "${TMSH}" modify ltm profile client-ssl "${ssl_profile}" \
            cert "${cert_obj}" \
            key "${key_obj}" \
            ${chain_arg}
    else
        log "  Criando perfil SSL client '${cert_name}_ssl'..."
        "${TMSH}" create ltm profile client-ssl "${ssl_profile}" \
            defaults-from clientssl \
            cert "${cert_obj}" \
            key "${key_obj}" \
            ${chain_arg}
    fi

    # -------------------------------------------------------------------------
    # Associar perfil SSL aos VSes HTTPS (se --vs-https foi passado)
    # -------------------------------------------------------------------------
    if [[ -n "${BIGIP_HTTPS_VS:-}" ]]; then
        for vs in ${BIGIP_HTTPS_VS}; do
            attach_ssl_profile_to_vs "${vs}" "${ssl_profile}"
        done
    else
        log "  Dica: use --vs-https /Common/<vs> para associar o perfil automaticamente."
    fi

    log "  Salvando configuração (tmsh save sys config)..."
    tmsh_cmd save sys config

    # Cutover confirmado — agora é seguro remover a versão anterior (best-effort)
    if [[ -n "${old_cert}" ]] && [[ "${old_cert}" != "${cert_obj}" ]]; then
        tmsh_cmd delete sys crypto cert "${old_cert}" 2>/dev/null \
            && log "  Removida versão anterior do certificado: ${old_cert}" \
            || log "  AVISO: não foi possível remover ${old_cert} (deixado para limpeza manual)."
    fi
    if [[ -n "${old_key}" ]] && [[ "${old_key}" != "${key_obj}" ]]; then
        tmsh_cmd delete sys crypto key "${old_key}" 2>/dev/null \
            && log "  Removida versão anterior da chave: ${old_key}" \
            || log "  AVISO: não foi possível remover ${old_key} (deixado para limpeza manual)."
    fi
    if [[ -n "${old_chain}" ]] && [[ "${old_chain}" != "${chain_obj}" ]]; then
        tmsh_cmd delete sys crypto cert "${old_chain}" 2>/dev/null || true
    fi

    mark_deploy_success "${domain}" "${certfile}"
    record_result "OK" "${event}" "${domain}" "instalado como versão ${timestamp}"

    log "deploy_cert: concluído para '${domain}'."
    log "  -> Cert :  ${cert_obj}"
    log "  -> Key  :  ${key_obj}"
    log "  -> Perfil: ${ssl_profile}"

    notify_rocketchat "✅ *bigip-acme*: certificado de *${domain}* renovado e implantado com sucesso (versão ${timestamp})." "good"
}

# =============================================================================
# attach_ssl_profile_to_vs VS_NAME SSL_PROFILE
#   Associa um perfil SSL client a um VS HTTPS (contexto clientside).
#   Usa "tmsh -c" para que os { } sejam interpretados pelo próprio tmsh.
# =============================================================================
attach_ssl_profile_to_vs() {
    local vs="${1}"
    local profile="${2}"

    if ! "${TMSH}" list ltm virtual "${vs}" &>/dev/null 2>&1; then
        log "  AVISO: VS HTTPS '${vs}' não encontrado. Ignorando."
        return
    fi

    # Verifica se o perfil já está no VS
    if "${TMSH}" list ltm virtual "${vs}" profiles 2>/dev/null | grep -qF "${profile}"; then
        log "  Perfil '${profile}' já está no VS '${vs}'."
        return
    fi

    log "  Associando perfil '${profile}' ao VS HTTPS '${vs}'..."
    # profiles add suporta o modificador "add" (diferente de "rules")
    "${TMSH}" -c "modify ltm virtual ${vs} profiles add { ${profile} { context clientside } }"
    log "  Perfil associado ao VS '${vs}'."
}

# =============================================================================
# unchanged_cert DOMAIN KEYFILE CERTFILE FULLCHAINFILE CHAINFILE TIMESTAMP
#   Chamado quando o dehydrated acha que o cert local ainda não precisa ser
#   renovado. Isso NÃO garante que o BIG-IP tenha o mesmo certificado — se o
#   deploy_cert de uma renovação anterior falhou depois do cert já ter sido
#   emitido/gravado localmente, o dehydrated segue achando tudo atualizado e
#   nunca mais tenta reimplantar sozinho. Por isso comparamos aqui o cert
#   local com o marcador do último deploy confirmado; se divergir, forçamos
#   o (re)deploy do cert atual mesmo sem reemitir nada na CA.
# =============================================================================
unchanged_cert() {
    local domain="${1}"
    local keyfile="${2}"
    local certfile="${3}"
    local fullchainfile="${4}"
    local chainfile="${5}"
    local timestamp="${6:-}"

    CURRENT_DOMAIN="${domain}"
    CURRENT_HOOK="unchanged_cert"

    log "unchanged_cert: '${domain}' ainda válido. Nenhuma ação necessária."

    local expiry
    expiry=$(openssl x509 -enddate -noout -in "${certfile}" 2>/dev/null | \
        cut -d= -f2 || echo "desconhecido")
    log "  Expira em: ${expiry}"

    if cert_deploy_drifted "${domain}" "${certfile}"; then
        log "  AVISO: sem confirmação de que o BIG-IP recebeu o último certificado de '${domain}'. Reimplantando..."
        notify_rocketchat "⚠️ *bigip-acme*: *${domain}* tem certificado local válido, mas sem confirmação de deploy no BIG-IP (provável falha anterior). Reimplantando automaticamente." "warning"
        deploy_cert "${domain}" "${keyfile}" "${certfile}" "${fullchainfile}" "${chainfile}" "${timestamp:-$(date +%s)}" "redeploy_drift"
        return
    fi

    record_result "OK" "unchanged_cert" "${domain}" "válido até ${expiry}"
}

# =============================================================================
# invalid_challenge DOMAIN TOKEN RESPONSE
# =============================================================================
invalid_challenge() {
    local domain="${1}"
    local token="${2}"
    local response="${3}"

    CURRENT_DOMAIN="${domain}"
    CURRENT_HOOK="invalid_challenge"

    log "ERRO invalid_challenge: falha na validação para '${domain}'. Resposta: ${response}"
    record_result "ERROR" "invalid_challenge" "${domain}" "${response}"
    notify_rocketchat "❌ *bigip-acme*: falha na validação ACME (challenge inválido) para *${domain}*.
Resposta da CA: ${response}" "danger"
}

# =============================================================================
# request_failure STATUSCODE BODY CHAIN
# =============================================================================
request_failure() {
    local status="${1}"
    local body="${2}"
    local chain="${3}"

    CURRENT_DOMAIN="${chain:-desconhecido}"
    CURRENT_HOOK="request_failure"

    log "ERRO request_failure: status=${status} chain=${chain}"
    log "  Corpo: ${body}"
    record_result "ERROR" "request_failure" "${chain:-desconhecido}" "HTTP ${status}: ${body}"
    notify_rocketchat "❌ *bigip-acme*: falha na requisição à CA (status ${status}).
Domínio(s): ${chain}
Corpo: ${body}" "danger"
}

# =============================================================================
# startup_hook / exit_hook
# =============================================================================
startup_hook() {
    log "startup_hook: dehydrated iniciado."
}

exit_hook() {
    local exit_code="${1:-0}"
    log "exit_hook: dehydrated finalizado (exit=${exit_code})."

    if [[ -n "${exit_code}" ]] && [[ "${exit_code}" != "0" ]]; then
        notify_rocketchat "⚠️ *bigip-acme*: dehydrated finalizou com problema: ${exit_code}" "warning"
    fi
}

# =============================================================================
# DISPATCHER — dehydrated chama este script com o nome do hook como $1
# =============================================================================
main() {
    local hook="${1}"
    shift

    case "${hook}" in
        deploy_challenge)   deploy_challenge "$@" ;;
        clean_challenge)    clean_challenge "$@" ;;
        deploy_cert)        deploy_cert "$@" ;;
        unchanged_cert)     unchanged_cert "$@" ;;
        invalid_challenge)  invalid_challenge "$@" ;;
        request_failure)    request_failure "$@" ;;
        startup_hook)       startup_hook ;;
        exit_hook)          exit_hook "$@" ;;
        *)
            log "Hook desconhecido: '${hook}' (args: $*) — ignorando."
            ;;
    esac
}

main "$@"
