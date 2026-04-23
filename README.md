# bigip-acme — Certificados ACME automáticos para F5 BIG-IP

Solução completa para emissão e renovação automática de certificados Let's Encrypt em F5 BIG-IP via protocolo ACME (HTTP-01 challenge), sem agentes externos nem acesso SSH de terceiros.

Testado em: **BIG-IP v17.5.x**

---

## Sumário

- [Como funciona](#como-funciona)
- [Pré-requisitos](#pré-requisitos)
- [Instalação](#instalação)
- [Setup inicial](#setup-inicial)
- [Gerenciar domínios pela interface](#gerenciar-domínios-pela-interface)
- [Monitoramento automático (Watch)](#monitoramento-automático-watch)
- [Renovação manual](#renovação-manual)
- [Remoção de domínios](#remoção-de-domínios)
- [Estrutura de arquivos](#estrutura-de-arquivos)
- [Objetos criados no BIG-IP](#objetos-criados-no-big-ip)
- [Referência de comandos](#referência-de-comandos)
- [Resolução de problemas](#resolução-de-problemas)

---

## Como funciona

```
┌─────────────────────────────────────────────────────────────┐
│  iCall handler (30s)                                        │
│       │                                                     │
│       ▼                                                     │
│  bigip-acme-watch.sh   ←── detecta mudança nos Data Groups │
│       │                                                     │
│       ▼                                                     │
│  bigip-acme.sh         ←── processa cada Data Group        │
│       │                                                     │
│       ├── cleanup: remove objetos de domínios apagados      │
│       │                                                     │
│       └── dehydrated ──► Let's Encrypt (HTTP-01)           │
│                │                                            │
│                └── bigip-hook.sh                           │
│                        ├── deploy_challenge: insere token   │
│                        │   no Data Group acme_challenges    │
│                        ├── iRule responde ao challenge      │
│                        └── deploy_cert: instala cert/key,  │
│                            cria/atualiza perfil SSL,        │
│                            associa ao VS HTTPS              │
└─────────────────────────────────────────────────────────────┘
```

**Fluxo de challenge HTTP-01:**

1. Let's Encrypt faz `GET /.well-known/acme-challenge/<token>` ao VS HTTP (porta 80)
2. A iRule `acme_challenge_handler` consulta o Data Group `acme_challenges`
3. Se o token estiver lá, responde `200 OK` com o `key-authorization`
4. Let's Encrypt valida e emite o certificado

---

## Pré-requisitos

- BIG-IP com acesso à internet (porta 443 de saída para `acme-v02.api.letsencrypt.org`)
- Virtual Server HTTP (porta 80) já existente para os domínios a certificar
- Virtual Server HTTPS (porta 443) já existente onde o certificado será instalado
- DNS dos domínios apontando para o IP do BIG-IP
- Acesso SSH ao BIG-IP com permissões de administrador (`tmsh`)

---

## Instalação

### 1. Copiar os scripts para o BIG-IP

```bash
# No seu computador — ajuste o IP do BIG-IP
scp bigip-acme.sh bigip-hook.sh bigip-acme-watch.sh \
    admin@<IP_BIGIP>:/shared/acme/
```

### 2. Ajustar permissões

```bash
# No BIG-IP
chmod +x /shared/acme/bigip-acme.sh
chmod +x /shared/acme/bigip-hook.sh
chmod +x /shared/acme/bigip-acme-watch.sh
```

### 3. Configurar e-mail de contato

```bash
# No BIG-IP — crie o arquivo .env
echo 'ACME_EMAIL=seu@email.com.br' > /shared/acme/.env
chmod 600 /shared/acme/.env
```

### 4. Ajustar fuso horário e NTP (recomendado)

```bash
tmsh modify sys ntp timezone America/Recife \
    servers replace-all-with { a.ntp.br b.ntp.br c.ntp.br } && \
tmsh save sys config
```

---

## Setup inicial

O setup é **idempotente** — pode ser executado múltiplas vezes sem efeito colateral.

### Setup básico

```bash
/shared/acme/bigip-acme.sh --setup \
    --vs /Common/<vs_http_porta_80> \
    --vs-https /Common/<vs_https_porta_443>
```

**Exemplo real:**

```bash
/shared/acme/bigip-acme.sh --setup \
    --vs /Common/vs_meu_bigip_http \
    --vs-https /Common/vs_meu_bigip_https
```

**O que o setup faz:**

| Ação | Objeto criado |
|------|---------------|
| Baixa o cliente ACME | `/shared/acme/dehydrated` |
| Cria Data Group de challenges | `/Common/acme_challenges` |
| Cria iRule de challenge | `/Common/acme_challenge_handler` |
| Anexa a iRule ao VS HTTP | modifica o VS existente |
| Cria Data Group de domínios | `/Common/acme_<vs_https_sanitizado>` |
| Registra conta no Let's Encrypt | `/shared/acme/accounts/` |

### Múltiplos VSes HTTP (porta 80)

Se vários VSes precisam responder ao challenge (ex: vários IPs):

```bash
/shared/acme/bigip-acme.sh --setup \
    --vs /Common/vs_site_a_http \
    --vs /Common/vs_site_b_http \
    --vs-https /Common/vs_site_a_https
```

### Múltiplos VSes HTTPS

Para diferentes VSes HTTPS (cada um recebe seu próprio Data Group de domínios):

```bash
/shared/acme/bigip-acme.sh --setup \
    --vs /Common/vs_http \
    --vs-https /Common/vs_site_a_https \
    --vs-https /Common/vs_site_b_https
```

### Ambiente de staging (testes sem rate-limit)

```bash
/shared/acme/bigip-acme.sh --setup --staging \
    --vs /Common/vs_http \
    --vs-https /Common/vs_https
```

---

## Gerenciar domínios pela interface

Os domínios são gerenciados via **Data Groups** na interface do BIG-IP, sem precisar editar arquivos ou rodar comandos a cada novo domínio.

### Acessar o Data Group

**Local Trafic > iRules > Data Group List**

Procure pelo Data Group com prefixo `acme_` seguido do nome do seu VS HTTPS.
Exemplo: `acme_vs_meu_bigip_https`

### Estrutura do Data Group

Cada Data Group contém:

| Chave (String) | Valor | Finalidade |
|----------------|-------|------------|
| `_vs_https` | `/Common/nome_do_vs` | Indica qual VS HTTPS receberá o certificado |
| `meusite.com.br` | *(vazio)* | Domínio a ser certificado |
| `meusite.com.br www.meusite.com.br` | *(vazio)* | Domínio + SANs no mesmo certificado |

> O registro `_vs_https` é criado automaticamente pelo setup. **Não remova.**

### Adicionar um domínio simples

**Via interface:**

1. Abra o Data Group `acme_*` correspondente
2. Clique em **Add**
3. **String:** `meusite.com.br`
4. **Value:** *(deixe vazio)*
5. Clique em **Add** e depois em **Update**

**Via tmsh:**

```bash
tmsh modify ltm data-group internal /Common/acme_vs_meu_bigip_https \
    records add { "meusite.com.br" { data "" } }
tmsh save sys config
```

### Adicionar domínio com SANs (múltiplos nomes no mesmo certificado)

**Via interface:**

1. **String:** `meusite.com.br www.meusite.com.br api.meusite.com.br`
2. **Value:** *(vazio)*

O primeiro domínio é o **Common Name**; os demais vão como SANs.

**Via tmsh:**

```bash
tmsh modify ltm data-group internal /Common/acme_vs_meu_bigip_https \
    records add { "meusite.com.br www.meusite.com.br" { data "" } }
tmsh save sys config
```

### Verificar domínios configurados

```bash
tmsh list ltm data-group internal /Common/acme_vs_meu_bigip_https
```

---

## Monitoramento automático (Watch)

O watch cria um **iCall handler** que verifica os Data Groups a cada 30 segundos. Quando detecta uma mudança, aciona a renovação automaticamente.

### Ativar o watch

```bash
WATCH_INTERVAL=30 /shared/acme/bigip-acme.sh --setup-watch
```

> O intervalo padrão é 60 segundos. Use `WATCH_INTERVAL=N` para ajustar.

### Verificar se o watch está ativo

```bash
tmsh list sys icall handler periodic acme_dg_watch_handler
tmsh list sys icall script acme_dg_watcher
```

Saída esperada:

```
sys icall handler periodic acme_dg_watch_handler {
    interval 30
    script acme_dg_watcher
}
```

### Acompanhar o log em tempo real

```bash
tail -f /shared/acme/logs/acme.log
```

Exemplo de log ao adicionar um domínio:

```
[2026-04-15 12:27:31] [watch] Mudança detectada nos Data Groups. Acionando renovação...
[2026-04-15 12:27:31] === Iniciando renovação de certificados ACME ===
[2026-04-15 12:27:33] Encontrados 1 Data Group(s): acme_vs_meu_bigip_https
[2026-04-15 12:27:39] --- Processando 'acme_vs_meu_bigip_https' → VS HTTPS: /Common/vs_meu_bigip_https ---
[2026-04-15 12:27:39] [hook] deploy_cert: instalando certificado para 'meusite.com.br'
[2026-04-15 12:27:40] [hook] deploy_cert: concluído para 'meusite.com.br'.
[2026-04-15 12:27:40] === Renovação concluída ===
```

### Desativar o watch

```bash
tmsh delete sys icall handler periodic acme_dg_watch_handler
tmsh delete sys icall script acme_dg_watcher
tmsh save sys config
```

---

## Renovação manual

Para forçar uma verificação/renovação imediata sem aguardar o watch:

```bash
/shared/acme/bigip-acme.sh
```

O script descobre automaticamente todos os Data Groups `acme_*` e verifica cada domínio. Certificados com mais de 30 dias de validade restante são mantidos sem renovar.

---

## Remoção de domínios

Quando um registro é removido do Data Group, o watch detecta a mudança e **remove automaticamente** todos os objetos BIG-IP associados:

- Perfil SSL client desassociado e deletado
- Certificado (`.crt`) deletado
- Chave privada (`.key`) deletada
- Chain (`.crt`) deletada
- Arquivos locais em `/shared/acme/certs/<dominio>/` removidos

### Como remover um domínio

**Via interface:**

1. Abra o Data Group `acme_*` correspondente
2. Marque o registro do domínio
3. Clique em **Delete** e depois em **Update**

**Via tmsh:**

```bash
tmsh modify ltm data-group internal /Common/acme_vs_meu_bigip_https \
    records delete { "meusite.com.br" }
tmsh save sys config
```

Em até 30 segundos (ou no intervalo configurado do watch), os objetos serão removidos automaticamente.

---

## Estrutura de arquivos

```
/shared/acme/
├── bigip-acme.sh          # Script principal — setup, renovação e limpeza
├── bigip-hook.sh          # Hook do dehydrated — challenge e instalação de cert
├── bigip-acme-watch.sh    # Watcher — detecta mudanças nos Data Groups
├── dehydrated             # Cliente ACME (baixado no setup)
├── dehydrated.conf        # Configuração do dehydrated (gerada no setup)
├── .env                   # Variáveis de ambiente (ACME_EMAIL, etc.)
├── .lock                  # Arquivo de lock (previne execuções simultâneas)
├── .dg_state              # Hash MD5 do estado dos Data Groups (usado pelo watch)
├── .state_<dg_name>.txt   # Lista de domínios por Data Group (usado para cleanup)
├── accounts/              # Conta registrada no Let's Encrypt
├── certs/                 # Certificados emitidos pelo dehydrated
│   └── meusite.com.br/
│       ├── cert.pem
│       ├── chain.pem
│       ├── fullchain.pem
│       └── privkey.pem
├── logs/
│   └── acme.log           # Log consolidado de todas as operações
└── wellknown/             # Diretório de challenges (não usado no modo BIG-IP)
```

---

## Objetos criados no BIG-IP

Para cada domínio `meusite.com.br` certificado:

| Tipo | Nome no BIG-IP |
|------|----------------|
| Certificado | `/Common/acme_meusite_com_br.crt` |
| Chave privada | `/Common/acme_meusite_com_br.key` |
| Chain | `/Common/acme_meusite_com_br-chain.crt` |
| Perfil SSL client | `/Common/acme_meusite_com_br_ssl` |

O perfil SSL é associado automaticamente ao VS HTTPS informado no Data Group (`_vs_https`).

**Objetos de infraestrutura** (criados no setup, compartilhados):

| Tipo | Nome |
|------|------|
| Data Group (challenges) | `/Common/acme_challenges` |
| Data Group (domínios) | `/Common/acme_<vs_https_sanitizado>` |
| iRule | `/Common/acme_challenge_handler` |
| iCall script | `acme_dg_watcher` |
| iCall handler | `acme_dg_watch_handler` |

---

## Referência de comandos

### Setup

```bash
# Setup básico
/shared/acme/bigip-acme.sh --setup \
    --vs /Common/<vs_http> \
    --vs-https /Common/<vs_https>

# Com staging (Let's Encrypt de teste)
/shared/acme/bigip-acme.sh --setup --staging \
    --vs /Common/<vs_http> \
    --vs-https /Common/<vs_https>

# Ativar watch automático (intervalo em segundos)
WATCH_INTERVAL=30 /shared/acme/bigip-acme.sh --setup-watch
```

### Domínios (tmsh)

```bash
# Adicionar domínio simples
tmsh modify ltm data-group internal /Common/acme_<dg> \
    records add { "dominio.com.br" { data "" } }

# Adicionar domínio com SANs
tmsh modify ltm data-group internal /Common/acme_<dg> \
    records add { "dominio.com.br www.dominio.com.br" { data "" } }

# Remover domínio
tmsh modify ltm data-group internal /Common/acme_<dg> \
    records delete { "dominio.com.br" }

# Listar domínios configurados
tmsh list ltm data-group internal /Common/acme_<dg>

# Salvar (obrigatório após modificações)
tmsh save sys config
```

### Monitoramento

```bash
# Log em tempo real
tail -f /shared/acme/logs/acme.log

# Apenas entradas do watcher
tail -f /shared/acme/logs/acme.log | grep watch

# Verificar watch ativo
tmsh list sys icall handler periodic acme_dg_watch_handler

# Forçar disparo do watcher (apaga estado)
rm /shared/acme/.dg_state

# Renovação manual imediata
/shared/acme/bigip-acme.sh
```

---

## Resolução de problemas

### Challenge falhou — `Connection refused` ou `404`

Verifique se:

1. A iRule `acme_challenge_handler` está anexada ao VS HTTP (porta 80)
2. O VS HTTP está ativo e o IP resolve para ele
3. O Data Group `acme_challenges` existe

```bash
tmsh list ltm virtual /Common/<vs_http> rules
tmsh list ltm data-group internal /Common/acme_challenges
```

### Perfil SSL não aparece no VS HTTPS

O perfil é associado automaticamente na emissão. Verifique o log:

```bash
grep "Associando perfil" /shared/acme/logs/acme.log
```

Se não houver entrada, confirme que o registro `_vs_https` no Data Group aponta para o VS correto:

```bash
tmsh list ltm data-group internal /Common/acme_<dg>
```

### Watch não dispara

```bash
# Confirmar que o handler existe
tmsh list sys icall handler periodic acme_dg_watch_handler

# Verificar se há erros recentes
grep -i erro /shared/acme/logs/acme.log | tail -20

# Forçar disparo manual
rm /shared/acme/.dg_state
```

### Erro `lock file` — outra instância em execução

```bash
rm -f /shared/acme/.lock
```

### Certificado não renova (ainda válido)

Por padrão, o dehydrated só renova com menos de **30 dias** de validade. Para forçar:

```bash
# Apagar o cert local para forçar reemissão
rm -rf /shared/acme/certs/<dominio>/
/shared/acme/bigip-acme.sh
```

### Rate limit do Let's Encrypt

Use o modo staging para testes:

```bash
/shared/acme/bigip-acme.sh --setup --staging \
    --vs /Common/<vs_http> \
    --vs-https /Common/<vs_https>
```

> O Let's Encrypt permite **5 certificados por domínio por semana** em produção. Em staging não há limite.
