#!/bin/bash

# ============================================================================
# REMNAWAVE NODE TLS SETUP — LE-серт через DNS-01 (Cloudflare) v1.0
# ============================================================================
#
# Этот скрипт выпускает Let's Encrypt сертификат на RemnaWave-ноде и настраивает
# автообновление с рестартом контейнера:
#
# 1. Диагностика текущего состояния
# 2. Установка certbot + dns-cloudflare плагина
# 3. Запись CF API-токена в /root/.secrets/cloudflare.ini
# 4. Создание deploy-hook (копирует cert в /opt/remnanode/certs/ + рестарт remnanode)
# 5. Volume mount /opt/remnanode/certs в docker-compose.yml (если нет)
# 6. Выпуск cert через DNS-01
# 7. Первый запуск deploy-hook вручную (certbot не вызывает hooks на первой выписке)
# 8. Проверка cert внутри контейнера + TLS-handshake
#
# Требуется: уже установленные Docker + Remnanode (запусти remnawave-node-setup.sh первым).
#
# Использование:
#   sudo ./remnawave-tls-setup.sh
#   sudo ./remnawave-tls-setup.sh --check-only
#   sudo ./remnawave-tls-setup.sh -d cdn.orbitalm.online -e admin@orbitalm.online -t <CF_TOKEN>
#
# Скачивание (после push):
#   curl -O https://raw.githubusercontent.com/Ravil346/repoforanal/main/remnawave-tls-setup.sh
#   chmod +x remnawave-tls-setup.sh
# ============================================================================

set -uo pipefail

SCRIPT_VERSION="1.0"

# === КОНФИГ ===
REMNANODE_DIR="/opt/remnanode"
CERTS_DIR="$REMNANODE_DIR/certs"
COMPOSE_FILE="$REMNANODE_DIR/docker-compose.yml"
CF_INI="/root/.secrets/cloudflare.ini"
DEPLOY_HOOK="/etc/letsencrypt/renewal-hooks/deploy/01-remnanode.sh"
LE_PROPAGATION_SECONDS=30

# === ВХОДНЫЕ ПАРАМЕТРЫ ===
DOMAIN=""
LE_EMAIL=""
CF_TOKEN=""
CHECK_ONLY=false
INTERACTIVE=true
FORCE_RENEW=false

# === СОСТОЯНИЕ ===
declare -A STATE
STATE[certbot]=false
STATE[dns_plugin]=false
STATE[cf_token]=false
STATE[deploy_hook]=false
STATE[volume_mount]=false
STATE[remnanode_running]=false
STATE[existing_certs]=""

# === ЦВЕТА ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "\n${BLUE}══════════════════════════════════════════════════════${NC}"
              echo -e "${BLUE}  $1${NC}"
              echo -e "${BLUE}══════════════════════════════════════════════════════${NC}"; }

show_header() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                                                                ║${NC}"
    echo -e "${BLUE}║     ${GREEN}REMNAWAVE NODE TLS SETUP — LE + Cloudflare DNS-01${BLUE}          ║${NC}"
    echo -e "${BLUE}║                       Версия ${SCRIPT_VERSION}                              ║${NC}"
    echo -e "${BLUE}║                                                                ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

show_help() {
    cat <<EOF
Использование: $0 [OPTIONS]

Опции:
  -d, --domain DOMAIN       Доменное имя для cert (обязательно)
  -e, --email EMAIL         Email для Let's Encrypt (по умолчанию admin@<root-domain>)
  -t, --token TOKEN         Cloudflare API token (если уже в $CF_INI — не нужен)
      --check-only          Только диагностика, никаких действий
      --non-interactive     Без вопросов (нужны все параметры через флаги)
      --force-renew         Перевыпустить cert, даже если уже существует
  -h, --help                Эта справка

Примеры:
  Интерактивно:
    sudo ./remnawave-tls-setup.sh

  Полностью неинтерактивно:
    sudo ./remnawave-tls-setup.sh \\
        -d cdn.orbitalm.online \\
        -e admin@orbitalm.online \\
        -t <CF_API_TOKEN> \\
        --non-interactive
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domain)        DOMAIN="$2"; shift 2 ;;
            -e|--email)         LE_EMAIL="$2"; shift 2 ;;
            -t|--token)         CF_TOKEN="$2"; shift 2 ;;
            --check-only)       CHECK_ONLY=true; shift ;;
            --non-interactive)  INTERACTIVE=false; shift ;;
            --force-renew)      FORCE_RENEW=true; shift ;;
            -h|--help)          show_help; exit 0 ;;
            *) log_warn "Неизвестный аргумент: $1"; shift ;;
        esac
    done
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Запусти от root: sudo $0"
        exit 1
    fi
}

# ============================================================================
# ДИАГНОСТИКА
# ============================================================================

diagnose() {
    log_step "ДИАГНОСТИКА"

    # certbot
    if command -v certbot &>/dev/null; then
        STATE[certbot]=true
        echo -e "  certbot:           ${GREEN}✓ установлен${NC}"
    else
        echo -e "  certbot:           ${YELLOW}✗ не установлен${NC}"
    fi

    # dns-cloudflare plugin
    if dpkg -l 2>/dev/null | grep -qE "^ii\s+python3-certbot-dns-cloudflare"; then
        STATE[dns_plugin]=true
        echo -e "  dns-cloudflare:    ${GREEN}✓ установлен${NC}"
    else
        echo -e "  dns-cloudflare:    ${YELLOW}✗ не установлен${NC}"
    fi

    # CF token
    if [[ -f "$CF_INI" ]] && grep -q "dns_cloudflare_api_token" "$CF_INI"; then
        STATE[cf_token]=true
        echo -e "  CF token:          ${GREEN}✓ есть ($CF_INI)${NC}"
    else
        echo -e "  CF token:          ${YELLOW}✗ нет ($CF_INI)${NC}"
    fi

    # deploy hook
    if [[ -x "$DEPLOY_HOOK" ]]; then
        STATE[deploy_hook]=true
        echo -e "  Deploy hook:       ${GREEN}✓ установлен${NC}"
    else
        echo -e "  Deploy hook:       ${YELLOW}✗ нет${NC}"
    fi

    # volume mount in compose
    if [[ -f "$COMPOSE_FILE" ]]; then
        if grep -qE "$CERTS_DIR\s*:\s*$CERTS_DIR" "$COMPOSE_FILE"; then
            STATE[volume_mount]=true
            echo -e "  Cert volume mount: ${GREEN}✓ есть в compose${NC}"
        else
            echo -e "  Cert volume mount: ${YELLOW}✗ нет в $COMPOSE_FILE${NC}"
        fi
    else
        echo -e "  Compose-файл:      ${RED}✗ не найден — запусти сначала remnawave-node-setup.sh${NC}"
    fi

    # remnanode container
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^remnanode$"; then
        STATE[remnanode_running]=true
        echo -e "  Remnanode:         ${GREEN}✓ запущен${NC}"
    else
        echo -e "  Remnanode:         ${YELLOW}⚠ не запущен${NC}"
    fi

    # existing certs
    if [[ -d /etc/letsencrypt/live ]]; then
        local existing
        existing=$(ls /etc/letsencrypt/live/ 2>/dev/null | grep -v "^README$" | tr '\n' ' ')
        if [[ -n "$existing" ]]; then
            STATE[existing_certs]="$existing"
            echo -e "  Существующие cert: ${GREEN}$existing${NC}"
        fi
    fi
    echo ""
}

# ============================================================================
# СБОР ИНФОРМАЦИИ
# ============================================================================

collect_info() {
    log_step "ВВОД ПАРАМЕТРОВ"

    # DOMAIN
    if [[ -z "$DOMAIN" ]]; then
        if [[ "$INTERACTIVE" != true ]]; then
            log_error "Доменное имя обязательно (--domain DOMAIN)"
            exit 1
        fi
        read -p "Доменное имя для cert (напр. cdn.orbitalm.online): " DOMAIN
    fi
    if [[ -z "$DOMAIN" ]]; then
        log_error "Домен не указан"
        exit 1
    fi

    # CF_TOKEN (если нет в файле и не передан флагом)
    if [[ "${STATE[cf_token]}" != true ]] && [[ -z "$CF_TOKEN" ]]; then
        if [[ "$INTERACTIVE" != true ]]; then
            log_error "CF token обязателен (--token TOKEN) — в $CF_INI его нет"
            exit 1
        fi
        local zone
        zone=$(echo "$DOMAIN" | awk -F. '{print $(NF-1)"."$NF}')
        echo ""
        echo "Cloudflare API token (создать в CF dashboard → My Profile → API Tokens →"
        echo "Create Token → шаблон 'Edit zone DNS', ограничить зоной: $zone):"
        read -rs -p "CF API Token: " CF_TOKEN
        echo
        if [[ -z "$CF_TOKEN" ]]; then
            log_error "Токен не указан"
            exit 1
        fi
    fi

    # LE_EMAIL
    if [[ -z "$LE_EMAIL" ]]; then
        local default_email
        default_email="admin@$(echo "$DOMAIN" | awk -F. '{print $(NF-1)"."$NF}')"
        if [[ "$INTERACTIVE" != true ]]; then
            LE_EMAIL="$default_email"
        else
            read -p "Email для LE [$default_email]: " LE_EMAIL
            LE_EMAIL=${LE_EMAIL:-$default_email}
        fi
    fi

    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo -e "  ${BOLD}План:${NC}"
    echo -e "  Домен:           ${GREEN}$DOMAIN${NC}"
    echo -e "  Email:           ${GREEN}$LE_EMAIL${NC}"
    echo -e "  Метод проверки:  DNS-01 (Cloudflare)"
    echo -e "  Cert хранится:   $CERTS_DIR/{fullchain,privkey}.pem"
    echo -e "  Auto-renewal:    certbot.timer + deploy hook"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo ""

    if [[ "$INTERACTIVE" == true ]]; then
        read -p "Продолжить? (yes/no): " confirm
        if [[ "$confirm" != "yes" ]]; then
            echo "Отменено."
            exit 0
        fi
    fi
}

# ============================================================================
# ШАГИ
# ============================================================================

install_packages() {
    if [[ "${STATE[certbot]}" == true ]] && [[ "${STATE[dns_plugin]}" == true ]]; then
        log_info "certbot + dns-cloudflare уже установлены"
        return
    fi
    log_step "УСТАНОВКА ПАКЕТОВ"
    apt-get update -qq
    apt-get install -y -qq python3-certbot-dns-cloudflare certbot rsync
    log_ok "certbot + dns-cloudflare установлены"
}

setup_cf_token() {
    if [[ "${STATE[cf_token]}" == true ]]; then
        log_info "CF token уже в $CF_INI"
        return
    fi
    log_step "ЗАПИСЬ CF API ТОКЕНА"
    mkdir -p "$(dirname "$CF_INI")"
    cat > "$CF_INI" <<EOF
dns_cloudflare_api_token = $CF_TOKEN
EOF
    chmod 600 "$CF_INI"
    log_ok "Токен записан в $CF_INI (chmod 600)"
}

setup_deploy_hook() {
    if [[ "${STATE[deploy_hook]}" == true ]]; then
        log_info "Deploy hook уже установлен ($DEPLOY_HOOK)"
        return
    fi
    log_step "СОЗДАНИЕ DEPLOY HOOK"
    mkdir -p "$(dirname "$DEPLOY_HOOK")" "$CERTS_DIR"
    cat > "$DEPLOY_HOOK" <<'HOOK_EOF'
#!/bin/bash
# Deploy hook для Remnanode: после renewal/выписки копирует cert
# в /opt/remnanode/certs/ и рестартит контейнер remnanode.
set -e

CERTS_DIR="/opt/remnanode/certs"
REMNANODE_DIR="/opt/remnanode"

if [[ -z "${RENEWED_LINEAGE:-}" ]]; then
    echo "RENEWED_LINEAGE не задан — выход" >&2
    exit 1
fi

mkdir -p "$CERTS_DIR"
cp "$RENEWED_LINEAGE/fullchain.pem" "$CERTS_DIR/fullchain.pem"
cp "$RENEWED_LINEAGE/privkey.pem"   "$CERTS_DIR/privkey.pem"
chmod 644 "$CERTS_DIR/fullchain.pem"
chmod 600 "$CERTS_DIR/privkey.pem"

if [[ -f "$REMNANODE_DIR/docker-compose.yml" ]]; then
    cd "$REMNANODE_DIR" && (docker compose restart remnanode || docker restart remnanode || true)
fi
HOOK_EOF
    chmod +x "$DEPLOY_HOOK"
    log_ok "Hook создан: $DEPLOY_HOOK"
}

ensure_volume_mount() {
    if [[ "${STATE[volume_mount]}" == true ]]; then
        log_info "Cert volume mount уже в compose"
        return
    fi
    log_step "ДОБАВЛЕНИЕ VOLUME MOUNT В COMPOSE"

    if [[ ! -f "$COMPOSE_FILE" ]]; then
        log_error "$COMPOSE_FILE не найден — сначала запусти remnawave-node-setup.sh"
        exit 1
    fi

    log_warn "В $COMPOSE_FILE нет монтирования cert'ов."
    log_info "Нужно добавить в секцию services.remnanode:"
    echo -e "${CYAN}    volumes:"
    echo -e "      - $CERTS_DIR:$CERTS_DIR:ro${NC}"
    echo ""

    if [[ "$INTERACTIVE" == true ]]; then
        read -p "Добавить автоматически (с бэкапом)? (y/N): " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            log_warn "Добавь вручную, рестартни remnanode (docker compose up -d) и запусти скрипт снова."
            exit 0
        fi
    fi

    # Бэкап
    cp "$COMPOSE_FILE" "$COMPOSE_FILE.backup.$(date +%Y%m%d_%H%M%S)"

    # Дописываем volumes в конец файла — для compose, созданного remnawave-node-setup.sh
    # это корректно: там одна service remnanode, и YAML-парсер прочтёт volumes как часть последней службы.
    # Если compose кастомный — пользователь должен править руками.
    cat >> "$COMPOSE_FILE" <<EOF
    volumes:
      - $CERTS_DIR:$CERTS_DIR:ro
EOF
    log_ok "Volume mount добавлен (бэкап рядом с .backup.*). Проверь $COMPOSE_FILE при сомнениях."

    log_info "Перезапускаю remnanode для применения mount'а..."
    (cd "$REMNANODE_DIR" && docker compose up -d) || {
        log_error "Не удалось перезапустить remnanode — проверь $COMPOSE_FILE"
        exit 1
    }
    sleep 2
}

issue_cert() {
    log_step "ВЫПУСК LE-СЕРТА"

    if [[ -d "/etc/letsencrypt/live/$DOMAIN" ]] && [[ "$FORCE_RENEW" != true ]]; then
        log_warn "Cert на $DOMAIN уже выпущен"
        if [[ "$INTERACTIVE" == true ]]; then
            read -p "Перевыпустить (force-renewal)? (y/N): " confirm
            if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                log_info "Использую существующий cert"
                return
            fi
            FORCE_RENEW=true
        else
            log_info "Использую существующий (--force-renew для перевыпуска)"
            return
        fi
    fi

    local force_flag=""
    [[ "$FORCE_RENEW" == true ]] && force_flag="--force-renewal"

    log_info "certbot certonly --dns-cloudflare -d $DOMAIN ..."
    certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials "$CF_INI" \
        --dns-cloudflare-propagation-seconds "$LE_PROPAGATION_SECONDS" \
        --email "$LE_EMAIL" \
        --agree-tos \
        --no-eff-email \
        --non-interactive \
        $force_flag \
        -d "$DOMAIN"

    if [[ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
        log_error "Cert не выпущен. Проверь: токен валиден? зона $DOMAIN на этом CF-аккаунте?"
        exit 1
    fi
    log_ok "Cert выпущен: /etc/letsencrypt/live/$DOMAIN/"
}

run_hook_manually() {
    log_step "ПЕРВЫЙ ЗАПУСК DEPLOY HOOK"
    log_info "Certbot не вызывает hooks на первой выписке — запускаю вручную."
    RENEWED_LINEAGE="/etc/letsencrypt/live/$DOMAIN" bash "$DEPLOY_HOOK"

    if [[ -f "$CERTS_DIR/fullchain.pem" ]] && [[ -f "$CERTS_DIR/privkey.pem" ]]; then
        log_ok "Cert скопирован в $CERTS_DIR/"
    else
        log_error "Hook не скопировал cert. Проверь $DEPLOY_HOOK вручную."
        exit 1
    fi
}

verify() {
    log_step "ПРОВЕРКА"

    sleep 2

    # Cert виден внутри контейнера?
    if docker exec remnanode test -f "$CERTS_DIR/fullchain.pem" 2>/dev/null; then
        log_ok "Cert виден внутри remnanode: $CERTS_DIR/fullchain.pem"
    else
        log_warn "Cert НЕ виден внутри remnanode. Проверь volume mount в $COMPOSE_FILE."
    fi

    # Subject/dates существующего cert'а
    echo ""
    log_info "Содержимое cert'а:"
    openssl x509 -in "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" -noout -subject -dates 2>/dev/null || true
    echo ""

    # TLS handshake на 127.0.0.1:443 (если Xray уже слушает с этим cert'ом)
    log_info "Пробую TLS-handshake на 127.0.0.1:443..."
    if echo | timeout 5 openssl s_client -connect 127.0.0.1:443 -servername "$DOMAIN" 2>/dev/null \
        | openssl x509 -noout -subject 2>/dev/null | grep -q "$DOMAIN"; then
        log_ok "TLS на :443 отдаёт правильный cert"
    else
        log_warn ":443 не отвечает или другой cert — это нормально, если профиль ноды в RemnaWave"
        log_warn "ещё не привязан к TLS-инбаунду на этом cert'е. Привяжи в панели."
    fi
}

final_report() {
    log_step "ГОТОВО"
    echo ""
    echo -e "  ${BOLD}Cert:${NC}                  ${GREEN}$DOMAIN${NC}"
    echo -e "  Host path:             ${CYAN}/etc/letsencrypt/live/$DOMAIN/${NC}"
    echo -e "  Container path:        ${CYAN}$CERTS_DIR/fullchain.pem${NC}"
    echo -e "                         ${CYAN}$CERTS_DIR/privkey.pem${NC}"
    echo -e "  Email:                 $LE_EMAIL"
    echo -e "  Auto-renewal:          ${GREEN}✓ certbot.timer (deploy hook рестартит remnanode)${NC}"
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  СЛЕДУЮЩИЕ ШАГИ:${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  1. В RemnaWave/Xray-профиле для этой ноды укажи cert:"
    echo -e "       fullchain: ${CYAN}$CERTS_DIR/fullchain.pem${NC}"
    echo -e "       privkey:   ${CYAN}$CERTS_DIR/privkey.pem${NC}"
    echo ""
    echo "  2. В Cloudflare DNS добавь A-запись:"
    echo -e "       ${CYAN}$DOMAIN${NC} → <публичный IP этой ноды>  (Proxy: DNS only, серое облако)"
    echo ""
    echo "  3. Через ~60 дней проверь авто-обновление (dry-run):"
    echo -e "       ${CYAN}sudo certbot renew --dry-run${NC}"
    echo ""
    echo -e "${GREEN}Готово.${NC}"
    echo ""
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    parse_args "$@"
    show_header
    check_root
    diagnose

    if [[ "$CHECK_ONLY" == true ]]; then
        log_info "Режим --check-only — действий не выполняю."
        exit 0
    fi

    collect_info
    install_packages
    setup_cf_token
    setup_deploy_hook
    ensure_volume_mount
    issue_cert
    run_hook_manually
    verify
    final_report
}

main "$@"
