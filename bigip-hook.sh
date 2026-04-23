#!/bin/bash
# =============================================================================
# bigip-hook.sh — Hook do dehydrated para F5 BIG-IP
#
# Callbacks implementados:
#   deploy_challenge   — adiciona token no Data Group para o iRule servir
#   clean_challenge    — remove o token do Data Group após validação
#   deploy_cert        — instala cert/key/chain via tmsh e atualiza perfil SSL
#   unchanged_cert     — log de que o cert ainda é válido (sem ação)
#   startup / exit_hook — reservados para log
#
# Variáveis esperadas do bigip-acme.sh:
#   BIGIP_PARTITION     — ex: "Common"
#   BIGIP_DATAGROUP     — ex: "acme_challenges"
#   BIGIP_OBJECT_PREFIX — ex: "acme"
# =============================================================================

set -euo pipefail

TMSH="/usr/bin/tmsh"
PARTITION="${BIGIP_PARTITION:-Common}"
DATAGROUP="${BIGIP_DATAGROUP:-acme_challenges}"
OBJECT_PREFIX="${BIGIP_OBJECT_PREFIX:-acme}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [hook] $*"
}

tmsh_cmd() {
    "${TMSH}" "$@"
}

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
# deploy_challenge DOMAIN TOKEN_FILENAME KEY_AUTH
#   Chamado para cada domínio antes da verificação ACME.
#   Insere o token no Data Group para que a iRule responda ao challenge.
# =============================================================================
deploy_challenge() {
    local domain="${1}"
    local token_file="${2}"
    local key_auth="${3}"

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

    log "clean_challenge: removendo token '${token_file}' do Data Group..."

    tmsh_cmd modify ltm data-group internal \
        "/${PARTITION}/${DATAGROUP}" \
        records delete { "${token_file}" } 2>&1 | \
        grep -v "^$" || true

    log "clean_challenge: token removido."
}

# =============================================================================
# deploy_cert DOMAIN KEYFILE CERTFILE FULLCHAINFILE CHAINFILE TIMESTAMP
#   Chamado após emissão/renovação bem-sucedida.
#   Instala o certificado no BIG-IP e atualiza o perfil SSL client.
# =============================================================================
deploy_cert() {
    local domain="${1}"
    local keyfile="${2}"
    local certfile="${3}"
    local fullchainfile="${4}"
    local chainfile="${5}"
    local timestamp="${6:-}"

    local cert_name
    cert_name="${OBJECT_PREFIX}_$(sanitize_name "${domain}")"
    local bigip_cert="/${PARTITION}/${cert_name}"

    # Nomes com extensão explícita — o tmsh install cria o objeto com o nome
    # exatamente como passado; o profile deve referenciar com o mesmo nome.
    local key_obj="${bigip_cert}.key"
    local cert_obj="${bigip_cert}.crt"
    local chain_obj="${bigip_cert}-chain.crt"

    log "deploy_cert: instalando certificado para '${domain}' como '${cert_name}'"

    # -------------------------------------------------------------------------
    # 1. Instalar chave privada (nome com .key explícito)
    # -------------------------------------------------------------------------
    log "  Instalando chave privada..."
    tmsh_cmd install sys crypto key "${key_obj}" from-local-file "${keyfile}"

    # -------------------------------------------------------------------------
    # 2. Instalar certificado leaf (nome com .crt explícito)
    # -------------------------------------------------------------------------
    log "  Instalando certificado..."
    tmsh_cmd install sys crypto cert "${cert_obj}" from-local-file "${certfile}"

    # -------------------------------------------------------------------------
    # 3. Instalar chain (nome com .crt explícito)
    # -------------------------------------------------------------------------
    local has_chain=false
    if [[ -f "${chainfile}" ]] && [[ -s "${chainfile}" ]]; then
        log "  Instalando chain..."
        tmsh_cmd install sys crypto cert "${chain_obj}" from-local-file "${chainfile}"
        has_chain=true
    fi

    # -------------------------------------------------------------------------
    # 4. Criar ou atualizar perfil SSL client
    # -------------------------------------------------------------------------
    local ssl_profile="${bigip_cert}_ssl"
    local ssl_profile_name="${cert_name}_ssl"

    # Monta argumento de chain apenas se existir
    local chain_arg=""
    ${has_chain} && chain_arg="chain ${chain_obj}"

    if "${TMSH}" list ltm profile client-ssl "${ssl_profile}" &>/dev/null 2>&1; then
        log "  Atualizando perfil SSL client '${ssl_profile_name}'..."
        "${TMSH}" modify ltm profile client-ssl "${ssl_profile}" \
            cert "${cert_obj}" \
            key "${key_obj}" \
            ${chain_arg}
    else
        log "  Criando perfil SSL client '${ssl_profile_name}'..."
        "${TMSH}" create ltm profile client-ssl "${ssl_profile}" \
            defaults-from clientssl \
            cert "${cert_obj}" \
            key "${key_obj}" \
            ${chain_arg}
    fi

    # -------------------------------------------------------------------------
    # 5. Associar perfil SSL aos VSes HTTPS (se --vs-https foi passado)
    # -------------------------------------------------------------------------
    if [[ -n "${BIGIP_HTTPS_VS:-}" ]]; then
        for vs in ${BIGIP_HTTPS_VS}; do
            attach_ssl_profile_to_vs "${vs}" "${ssl_profile}"
        done
    else
        log "  Dica: use --vs-https /Common/<vs> para associar o perfil automaticamente."
    fi

    # -------------------------------------------------------------------------
    # 6. Salvar configuração
    # -------------------------------------------------------------------------
    log "  Salvando configuração (tmsh save sys config)..."
    tmsh_cmd save sys config

    log "deploy_cert: concluído para '${domain}'."
    log "  -> Cert :  ${cert_obj}"
    log "  -> Key  :  ${key_obj}"
    log "  -> Perfil: ${ssl_profile}"
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
#   Chamado quando o cert ainda não precisa ser renovado.
# =============================================================================
unchanged_cert() {
    local domain="${1}"
    local keyfile="${2}"
    local certfile="${3}"
    local fullchainfile="${4}"
    local chainfile="${5}"
    local timestamp="${6:-}"

    log "unchanged_cert: '${domain}' ainda válido. Nenhuma ação necessária."

    # Verifica a validade do cert atual e loga
    local expiry
    expiry=$(openssl x509 -enddate -noout -in "${certfile}" 2>/dev/null | \
        cut -d= -f2 || echo "desconhecido")
    log "  Expira em: ${expiry}"
}

# =============================================================================
# invalid_challenge DOMAIN TOKEN RESPONSE
# =============================================================================
invalid_challenge() {
    local domain="${1}"
    local token="${2}"
    local response="${3}"
    log "ERRO invalid_challenge: falha na validação para '${domain}'. Resposta: ${response}"
}

# =============================================================================
# request_failure STATUSCODE BODY CHAIN
# =============================================================================
request_failure() {
    local status="${1}"
    local body="${2}"
    local chain="${3}"
    log "ERRO request_failure: status=${status} chain=${chain}"
    log "  Corpo: ${body}"
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
