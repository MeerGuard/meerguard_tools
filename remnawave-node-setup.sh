#!/bin/bash

# ============================================================================
# REMNAWAVE NODE SETUP - UNIFIED INSTALLER v2.0
# ============================================================================
# 
# Этот скрипт объединяет все операции по настройке ноды:
# 1. Диагностика текущего состояния
# 2. Оптимизация системы (BBR, TCP buffers, swap)
# 3. Установка Docker (официальный метод)
# 4. Установка RemnaWave Node
# 5. Настройка безопасности (SSH, UFW)
# 6. Установка AmneziaWG туннеля
# 7. Установка Promtail для логов
#
# Особенности:
# - Диагностика ПЕРЕД установкой
# - Пропуск уже установленных компонентов
# - Детальный отчёт о состоянии системы
#
# Скачивание:
# curl -O https://raw.githubusercontent.com/Ravil346/repoforanal/main/remnawave-node-setup.sh && chmod +x remnawave-node-setup.sh
# 
# Использование:
#   ./remnawave-node-setup.sh
#   ./remnawave-node-setup.sh --skip-awg
#   ./remnawave-node-setup.sh --skip-promtail
#   ./remnawave-node-setup.sh --diagnostic-only  # Только диагностика
# ============================================================================

set -uo pipefail

# === КОНФИГУРАЦИЯ ===
SCRIPT_VERSION="2.0"
PANEL_IP="91.208.184.247"
PANEL_AWG_PORT="51820"
PANEL_AWG_PUBKEY="1ZTPs2CbwJfwF8AUuGd3YEQA8YPWV4UKwqVHc/Fn3Cg="
VICTORIA_URL="http://10.10.0.1:9428/insert/loki/api/v1/push"

NEW_SSH_PORT=41022
NEW_NODE_PORT=47891
VPN_PORT=443

REMNANODE_DIR="/opt/remnanode"

# === ФЛАГИ ===
SKIP_AWG=false
SKIP_PROMTAIL=false
SKIP_SECURITY=false
SKIP_OPTIMIZATION=false
DIAGNOSTIC_ONLY=false
INTERACTIVE=true

# === СОСТОЯНИЕ СИСТЕМЫ (заполняется при диагностике) ===
declare -A STATE
STATE[docker_installed]=false
STATE[docker_version]=""
STATE[docker_compose_installed]=false
STATE[docker_compose_version]=""
STATE[remnanode_installed]=false
STATE[remnanode_running]=false
STATE[awg_installed]=false
STATE[awg_module_loaded]=false
STATE[awg_tunnel_active]=false
STATE[promtail_installed]=false
STATE[promtail_running]=false
STATE[ufw_installed]=false
STATE[ufw_active]=false
STATE[ssh_port]=""
STATE[bbr_enabled]=false
STATE[optimization_applied]=false
STATE[os_name]=""
STATE[os_version]=""
STATE[kernel_version]=""
STATE[cpu_cores]=""
STATE[ram_total]=""
STATE[disk_free]=""
STATE[public_ip]=""

# === ЦВЕТА ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# === ФУНКЦИИ ЛОГИРОВАНИЯ ===
log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "\n${BLUE}══════════════════════════════════════════════════════${NC}"; echo -e "${BLUE}  $1${NC}"; echo -e "${BLUE}══════════════════════════════════════════════════════${NC}"; }
log_substep() { echo -e "\n${CYAN}--- $1 ---${NC}"; }

# === HEADER ===
show_header() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                                                                ║${NC}"
    echo -e "${BLUE}║       ${GREEN}REMNAWAVE NODE SETUP - UNIFIED INSTALLER${BLUE}                ║${NC}"
    echo -e "${BLUE}║                     Версия ${SCRIPT_VERSION}                              ║${NC}"
    echo -e "${BLUE}║                                                                ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# === ПАРСИНГ АРГУМЕНТОВ ===
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-awg) SKIP_AWG=true; shift ;;
            --skip-promtail) SKIP_PROMTAIL=true; shift ;;
            --skip-security) SKIP_SECURITY=true; shift ;;
            --skip-optimization) SKIP_OPTIMIZATION=true; shift ;;
            --diagnostic-only) DIAGNOSTIC_ONLY=true; shift ;;
            --non-interactive) INTERACTIVE=false; shift ;;
            -h|--help) show_help; exit 0 ;;
            *) shift ;;
        esac
    done
}

show_help() {
    echo "Использование: $0 [OPTIONS]"
    echo ""
    echo "Опции:"
    echo "  --skip-awg          Пропустить установку AmneziaWG"
    echo "  --skip-promtail     Пропустить установку Promtail"
    echo "  --skip-security     Пропустить настройку безопасности"
    echo "  --skip-optimization Пропустить оптимизацию системы"
    echo "  --diagnostic-only   Только диагностика (без установки)"
    echo "  --non-interactive   Неинтерактивный режим"
    echo "  -h, --help          Показать эту справку"
}

# === ПРОВЕРКА ROOT ===
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Запустите скрипт от root: sudo bash $0"
        exit 1
    fi
}

# ============================================================================
# ДИАГНОСТИКА СИСТЕМЫ
# ============================================================================

run_diagnostics() {
    log_step "ДИАГНОСТИКА СИСТЕМЫ"
    
    log_substep "Информация о системе"
    
    # ОС
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        STATE[os_name]="$ID"
        STATE[os_version]="$VERSION_ID"
    fi
    echo -e "  ОС:              ${GREEN}${STATE[os_name]} ${STATE[os_version]}${NC}"
    
    # Ядро
    STATE[kernel_version]=$(uname -r)
    echo -e "  Ядро:            ${GREEN}${STATE[kernel_version]}${NC}"
    
    # CPU
    STATE[cpu_cores]=$(nproc)
    echo -e "  CPU ядра:        ${GREEN}${STATE[cpu_cores]}${NC}"
    
    # RAM
    STATE[ram_total]=$(free -h | awk '/^Mem:/{print $2}')
    echo -e "  RAM:             ${GREEN}${STATE[ram_total]}${NC}"
    
    # Disk
    STATE[disk_free]=$(df -h / | awk 'NR==2{print $4}')
    echo -e "  Диск свободно:   ${GREEN}${STATE[disk_free]}${NC}"
    
    # Public IP
    STATE[public_ip]=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || echo "не определён")
    echo -e "  Публичный IP:    ${GREEN}${STATE[public_ip]}${NC}"
    
    # === Docker ===
    log_substep "Docker"
    
    if command -v docker &> /dev/null; then
        STATE[docker_installed]=true
        STATE[docker_version]=$(docker --version 2>/dev/null | grep -oP 'Docker version \K[0-9.]+' || echo "unknown")
        echo -e "  Docker:          ${GREEN}✓ установлен (${STATE[docker_version]})${NC}"
        
        if systemctl is-active docker &>/dev/null; then
            echo -e "  Docker сервис:   ${GREEN}✓ запущен${NC}"
        else
            echo -e "  Docker сервис:   ${YELLOW}⚠ не запущен${NC}"
        fi
    else
        STATE[docker_installed]=false
        echo -e "  Docker:          ${YELLOW}✗ не установлен${NC}"
    fi
    
    # Docker Compose
    if docker compose version &> /dev/null 2>&1; then
        STATE[docker_compose_installed]=true
        STATE[docker_compose_version]=$(docker compose version --short 2>/dev/null || echo "unknown")
        echo -e "  Docker Compose:  ${GREEN}✓ установлен (${STATE[docker_compose_version]})${NC}"
    elif command -v docker-compose &> /dev/null; then
        STATE[docker_compose_installed]=true
        STATE[docker_compose_version]=$(docker-compose --version 2>/dev/null | grep -oP '[0-9.]+' | head -1 || echo "unknown")
        echo -e "  Docker Compose:  ${GREEN}✓ установлен (legacy ${STATE[docker_compose_version]})${NC}"
    else
        STATE[docker_compose_installed]=false
        echo -e "  Docker Compose:  ${YELLOW}✗ не установлен${NC}"
    fi
    
    # === RemnaWave Node ===
    log_substep "RemnaWave Node"
    
    if [[ -f "$REMNANODE_DIR/docker-compose.yml" ]]; then
        STATE[remnanode_installed]=true
        echo -e "  Конфигурация:    ${GREEN}✓ найдена в $REMNANODE_DIR${NC}"
        
        # Проверяем контейнер
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^remnanode$"; then
            STATE[remnanode_running]=true
            echo -e "  Контейнер:       ${GREEN}✓ запущен${NC}"
            
            # Версия образа
            local image_ver=$(docker inspect remnanode --format '{{.Config.Image}}' 2>/dev/null || echo "unknown")
            echo -e "  Образ:           ${GREEN}$image_ver${NC}"
        else
            STATE[remnanode_running]=false
            echo -e "  Контейнер:       ${YELLOW}⚠ не запущен${NC}"
        fi
        
        # NODE_PORT из конфига
        local current_port=$(grep -oP 'NODE_PORT[=:]\s*"?\K[0-9]+' "$REMNANODE_DIR/docker-compose.yml" 2>/dev/null | head -1)
        if [[ -n "$current_port" ]]; then
            echo -e "  NODE_PORT:       ${GREEN}$current_port${NC}"
        fi
    else
        STATE[remnanode_installed]=false
        echo -e "  Конфигурация:    ${YELLOW}✗ не найдена${NC}"
    fi
    
    # === AmneziaWG ===
    log_substep "AmneziaWG"
    
    if command -v awg &> /dev/null; then
        STATE[awg_installed]=true
        echo -e "  AWG tools:       ${GREEN}✓ установлены${NC}"
        
        if lsmod | grep -q amneziawg; then
            STATE[awg_module_loaded]=true
            echo -e "  AWG модуль:      ${GREEN}✓ загружен${NC}"
        else
            STATE[awg_module_loaded]=false
            echo -e "  AWG модуль:      ${YELLOW}⚠ не загружен${NC}"
        fi
        
        if ip link show awg0 &>/dev/null; then
            STATE[awg_tunnel_active]=true
            local awg_ip=$(ip addr show awg0 2>/dev/null | grep -oP 'inet \K[0-9.]+' || echo "unknown")
            echo -e "  AWG туннель:     ${GREEN}✓ активен ($awg_ip)${NC}"
            
            # Проверка связи с панелью
            if ping -c 1 -W 2 10.10.0.1 &>/dev/null; then
                echo -e "  Связь с панелью: ${GREEN}✓ есть${NC}"
            else
                echo -e "  Связь с панелью: ${YELLOW}⚠ нет (добавь пир на панели)${NC}"
            fi
        else
            STATE[awg_tunnel_active]=false
            echo -e "  AWG туннель:     ${YELLOW}⚠ не активен${NC}"
        fi
        
        # Публичный ключ
        if [[ -f /etc/amnezia/amneziawg/publickey ]]; then
            local pubkey=$(cat /etc/amnezia/amneziawg/publickey)
            echo -e "  Публичный ключ:  ${CYAN}$pubkey${NC}"
        fi
    else
        STATE[awg_installed]=false
        echo -e "  AmneziaWG:       ${YELLOW}✗ не установлен${NC}"
    fi
    
    # === Promtail ===
    log_substep "Promtail"
    
    if [[ -f "$REMNANODE_DIR/docker-compose.override.yml" ]] && grep -q promtail "$REMNANODE_DIR/docker-compose.override.yml" 2>/dev/null; then
        STATE[promtail_installed]=true
        echo -e "  Конфигурация:    ${GREEN}✓ найдена${NC}"
        
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^promtail$"; then
            STATE[promtail_running]=true
            echo -e "  Контейнер:       ${GREEN}✓ запущен${NC}"
        else
            STATE[promtail_running]=false
            echo -e "  Контейнер:       ${YELLOW}⚠ не запущен${NC}"
        fi
    else
        STATE[promtail_installed]=false
        echo -e "  Promtail:        ${YELLOW}✗ не установлен${NC}"
    fi
    
    # === UFW / Безопасность ===
    log_substep "Безопасность"
    
    if command -v ufw &> /dev/null; then
        STATE[ufw_installed]=true
        echo -e "  UFW:             ${GREEN}✓ установлен${NC}"
        
        if ufw status | grep -q "Status: active"; then
            STATE[ufw_active]=true
            echo -e "  UFW статус:      ${GREEN}✓ активен${NC}"
            
            # Показать правила
            echo -e "  Правила UFW:"
            ufw status | grep -E "^[0-9]|ALLOW|DENY" | head -10 | while read line; do
                echo -e "    ${CYAN}$line${NC}"
            done
        else
            STATE[ufw_active]=false
            echo -e "  UFW статус:      ${YELLOW}⚠ не активен${NC}"
        fi
    else
        STATE[ufw_installed]=false
        echo -e "  UFW:             ${YELLOW}✗ не установлен${NC}"
    fi
    
    # SSH порт
    STATE[ssh_port]=$(grep -E "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [[ -z "${STATE[ssh_port]}" ]]; then
        STATE[ssh_port]="22 (по умолчанию)"
    fi
    echo -e "  SSH порт:        ${GREEN}${STATE[ssh_port]}${NC}"
    
    # SSH на IPv4?
    if ss -tlnp | grep -q "0.0.0.0:${STATE[ssh_port]%% *}"; then
        echo -e "  SSH IPv4:        ${GREEN}✓ слушает${NC}"
    elif ss -tlnp | grep -q "\[::\]:${STATE[ssh_port]%% *}"; then
        echo -e "  SSH IPv4:        ${YELLOW}⚠ только IPv6${NC}"
    fi
    
    # === Оптимизация ===
    log_substep "Оптимизация системы"
    
    # BBR
    local current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
    if [[ "$current_cc" == "bbr" ]]; then
        STATE[bbr_enabled]=true
        echo -e "  BBR:             ${GREEN}✓ включён${NC}"
    else
        STATE[bbr_enabled]=false
        echo -e "  BBR:             ${YELLOW}✗ не включён ($current_cc)${NC}"
    fi
    
    # TCP buffers
    local rmem=$(sysctl -n net.core.rmem_max 2>/dev/null || echo "0")
    if [[ "$rmem" -ge 16777216 ]]; then
        echo -e "  TCP buffers:     ${GREEN}✓ оптимизированы${NC}"
        STATE[optimization_applied]=true
    else
        echo -e "  TCP buffers:     ${YELLOW}✗ не оптимизированы (rmem_max=$rmem)${NC}"
    fi
    
    # Docker limits
    if [[ -f /etc/systemd/system/docker.service.d/limits.conf ]]; then
        echo -e "  Docker limits:   ${GREEN}✓ настроены${NC}"
    else
        echo -e "  Docker limits:   ${YELLOW}✗ не настроены${NC}"
    fi
    
    # === Сводка ===
    log_substep "СВОДКА"
    
    echo ""
    echo -e "  ${BOLD}Компонент          Статус${NC}"
    echo -e "  ─────────────────────────────────────"
    
    # Docker
    if [[ "${STATE[docker_installed]}" == true ]]; then
        echo -e "  Docker           ${GREEN}✓ OK${NC}"
    else
        echo -e "  Docker           ${YELLOW}⬤ Требуется установка${NC}"
    fi
    
    # RemnaWave Node
    if [[ "${STATE[remnanode_running]}" == true ]]; then
        echo -e "  RemnaWave Node   ${GREEN}✓ OK${NC}"
    elif [[ "${STATE[remnanode_installed]}" == true ]]; then
        echo -e "  RemnaWave Node   ${YELLOW}⬤ Не запущен${NC}"
    else
        echo -e "  RemnaWave Node   ${YELLOW}⬤ Требуется установка${NC}"
    fi
    
    # Безопасность
    if [[ "${STATE[ufw_active]}" == true ]] && [[ "${STATE[ssh_port]}" == "$NEW_SSH_PORT"* ]]; then
        echo -e "  Безопасность     ${GREEN}✓ OK${NC}"
    elif [[ "${STATE[ufw_active]}" == true ]]; then
        echo -e "  Безопасность     ${YELLOW}⬤ UFW активен, SSH на ${STATE[ssh_port]}${NC}"
    else
        echo -e "  Безопасность     ${YELLOW}⬤ Требуется настройка${NC}"
    fi
    
    # AWG
    if [[ "${STATE[awg_tunnel_active]}" == true ]]; then
        echo -e "  AmneziaWG        ${GREEN}✓ OK${NC}"
    elif [[ "${STATE[awg_installed]}" == true ]]; then
        echo -e "  AmneziaWG        ${YELLOW}⬤ Установлен, туннель не активен${NC}"
    else
        echo -e "  AmneziaWG        ${YELLOW}⬤ Требуется установка${NC}"
    fi
    
    # Promtail
    if [[ "${STATE[promtail_running]}" == true ]]; then
        echo -e "  Promtail         ${GREEN}✓ OK${NC}"
    elif [[ "${STATE[promtail_installed]}" == true ]]; then
        echo -e "  Promtail         ${YELLOW}⬤ Установлен, не запущен${NC}"
    else
        echo -e "  Promtail         ${YELLOW}⬤ Требуется установка${NC}"
    fi
    
    # Оптимизация
    if [[ "${STATE[bbr_enabled]}" == true ]] && [[ "${STATE[optimization_applied]}" == true ]]; then
        echo -e "  Оптимизация      ${GREEN}✓ OK${NC}"
    else
        echo -e "  Оптимизация      ${YELLOW}⬤ Требуется${NC}"
    fi
    
    echo ""
}

# ============================================================================
# СБОР ИНФОРМАЦИИ ДЛЯ УСТАНОВКИ
# ============================================================================

collect_info() {
    log_step "СБОР ИНФОРМАЦИИ"
    
    # Имя ноды
    echo ""
    echo "Доступные имена нод и их AWG IP:"
    echo "  node-de     - Германия     (10.10.0.2)"
    echo "  node-nl     - Нидерланды   (10.10.0.3)"
    echo "  node-us     - США          (10.10.0.4)"
    echo "  node-us2    - США 2        (10.10.0.8)"
    echo "  node-ru     - Россия       (10.10.0.5)"
    echo "  node-in     - Индия        (10.10.0.6)"
    echo "  node-kr     - Южная Корея  (10.10.0.7)"
    echo ""
    
    read -p "Введи имя ноды: " NODE_NAME
    NODE_NAME=${NODE_NAME:-"node-unknown"}
    
    # AWG IP на основе имени ноды
    case $NODE_NAME in
        node-de|de|germany)   NODE_AWG_IP="10.10.0.2"; NODE_NAME="node-de" ;;
        node-nl|nl|netherlands) NODE_AWG_IP="10.10.0.3"; NODE_NAME="node-nl" ;;
        node-us|us|usa)       NODE_AWG_IP="10.10.0.4"; NODE_NAME="node-us" ;;
        node-us2|us2|usa2)    NODE_AWG_IP="10.10.0.8"; NODE_NAME="node-us2" ;;
        node-ru|ru|russia)    NODE_AWG_IP="10.10.0.5"; NODE_NAME="node-ru" ;;
        node-in|in|india)     NODE_AWG_IP="10.10.0.6"; NODE_NAME="node-in" ;;
        node-kr|kr|korea)     NODE_AWG_IP="10.10.0.7"; NODE_NAME="node-kr" ;;
        *)
            echo ""
            read -p "AWG IP для этой ноды (например 10.10.0.X): " NODE_AWG_IP
            ;;
    esac
    
    log_ok "Нода: $NODE_NAME, AWG IP: $NODE_AWG_IP"
    
    # VPN порт (для xHTTP)
    echo ""
    read -p "Нужен дополнительный порт 8443 (xHTTP)? (y/N): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        EXTRA_VPN_PORT=8443
    else
        EXTRA_VPN_PORT=""
    fi
    
    # Если RemnaWave Node уже установлен, спросить о переустановке
    if [[ "${STATE[remnanode_installed]}" == true ]]; then
        echo ""
        echo -e "${YELLOW}RemnaWave Node уже установлен в $REMNANODE_DIR${NC}"
        read -p "Переустановить? (y/N): " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            SKIP_NODE_INSTALL=true
        else
            SKIP_NODE_INSTALL=false
        fi
    else
        SKIP_NODE_INSTALL=false
    fi
    
    # Docker compose из панели (только если нужна установка ноды)
    if [[ "$SKIP_NODE_INSTALL" != true ]]; then
        echo ""
        echo -e "${YELLOW}Скопируй docker-compose из панели RemnaWave:${NC}"
        echo "  1. Открой панель → Nodes → твоя нода → Important info"
        echo "  2. Скопируй весь docker-compose.yml"
        echo ""
        echo "Вставь docker-compose.yml (завершение: пустая строка + Enter):"
        echo ""
        
        COMPOSE_CONTENT=""
        while IFS= read -r line; do
            [[ -z "$line" ]] && break
            COMPOSE_CONTENT+="$line"$'\n'
        done
        
        # Извлекаем SECRET_KEY
        SECRET_KEY=$(echo "$COMPOSE_CONTENT" | grep -oP 'SECRET_KEY="\K[^"]+' || echo "")
        
        if [[ -z "$SECRET_KEY" ]]; then
            log_error "SECRET_KEY не найден в docker-compose!"
            echo "Убедись, что скопировал весь compose из панели."
            exit 1
        fi
        
        log_ok "SECRET_KEY извлечён (${#SECRET_KEY} символов)"
    fi
    
    # Подтверждение
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo -e "  ${BOLD}План установки:${NC}"
    echo -e "  Нода:           ${GREEN}$NODE_NAME${NC}"
    echo -e "  AWG IP:         ${GREEN}$NODE_AWG_IP${NC}"
    echo -e "  SSH порт:       ${GREEN}$NEW_SSH_PORT${NC}"
    echo -e "  Node порт:      ${GREEN}$NEW_NODE_PORT${NC}"
    echo -e "  VPN порты:      ${GREEN}$VPN_PORT ${EXTRA_VPN_PORT}${NC}"
    echo ""
    echo -e "  ${BOLD}Что будет сделано:${NC}"
    
    # Оптимизация
    if [[ "$SKIP_OPTIMIZATION" != true ]] && [[ "${STATE[bbr_enabled]}" != true || "${STATE[optimization_applied]}" != true ]]; then
        echo -e "  ${GREEN}✓${NC} Оптимизация системы (BBR, TCP buffers)"
    else
        echo -e "  ${CYAN}→${NC} Оптимизация: пропуск (уже применена)"
    fi
    
    # Docker
    if [[ "${STATE[docker_installed]}" != true ]]; then
        echo -e "  ${GREEN}✓${NC} Установка Docker"
    else
        echo -e "  ${CYAN}→${NC} Docker: пропуск (уже установлен)"
    fi
    
    # RemnaWave Node
    if [[ "$SKIP_NODE_INSTALL" != true ]]; then
        echo -e "  ${GREEN}✓${NC} Установка RemnaWave Node"
    else
        echo -e "  ${CYAN}→${NC} RemnaWave Node: пропуск"
    fi
    
    # Безопасность
    if [[ "$SKIP_SECURITY" != true ]]; then
        echo -e "  ${GREEN}✓${NC} Настройка безопасности (SSH, UFW)"
    else
        echo -e "  ${CYAN}→${NC} Безопасность: пропуск"
    fi
    
    # AWG
    if [[ "$SKIP_AWG" != true ]]; then
        if [[ "${STATE[awg_installed]}" != true ]]; then
            echo -e "  ${GREEN}✓${NC} Установка AmneziaWG"
        else
            echo -e "  ${CYAN}→${NC} AWG: настройка (уже установлен)"
        fi
    else
        echo -e "  ${CYAN}→${NC} AmneziaWG: пропуск"
    fi
    
    # Promtail
    if [[ "$SKIP_PROMTAIL" != true ]]; then
        if [[ "${STATE[promtail_installed]}" != true ]]; then
            echo -e "  ${GREEN}✓${NC} Установка Promtail"
        else
            echo -e "  ${CYAN}→${NC} Promtail: пропуск (уже установлен)"
        fi
    else
        echo -e "  ${CYAN}→${NC} Promtail: пропуск"
    fi
    
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
# ЧАСТЬ 1: ОПТИМИЗАЦИЯ СИСТЕМЫ
# ============================================================================

optimize_system() {
    if [[ "$SKIP_OPTIMIZATION" == true ]]; then
        log_info "Пропуск оптимизации (--skip-optimization)"
        return
    fi
    
    # Проверяем нужна ли оптимизация
    if [[ "${STATE[bbr_enabled]}" == true ]] && [[ "${STATE[optimization_applied]}" == true ]]; then
        log_info "Оптимизация уже применена, пропускаю"
        return
    fi
    
    log_step "ОПТИМИЗАЦИЯ СИСТЕМЫ"
    
    # BBR
    if [[ "${STATE[bbr_enabled]}" != true ]]; then
        log_info "Настройка BBR..."
        modprobe tcp_bbr 2>/dev/null || log_warn "Не удалось загрузить tcp_bbr"
        echo "tcp_bbr" > /etc/modules-load.d/bbr.conf 2>/dev/null || true
        log_ok "BBR настроен"
    else
        log_ok "BBR уже включён"
    fi
    
    # Sysctl
    log_info "Применение sysctl настроек..."
    cat > /etc/sysctl.d/99-vpn-optimization.conf << 'EOF'
# VPN Node Optimization
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 16384
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_forward = 1

# Swap только как страховка от OOM, не для постоянного использования
vm.swappiness = 10
EOF
    sysctl -p /etc/sysctl.d/99-vpn-optimization.conf > /dev/null 2>&1 || true
    log_ok "Sysctl настройки применены"
    
    # Docker limits
    log_info "Настройка лимитов Docker..."
    mkdir -p /etc/systemd/system/docker.service.d
    cat > /etc/systemd/system/docker.service.d/limits.conf << 'EOF'
[Service]
LimitNOFILE=65535
LimitNPROC=65535
EOF
    systemctl daemon-reload
    log_ok "Лимиты Docker настроены"

    # Swap — страховка от OOM-killer при пиках памяти
    log_info "Проверка swap..."
    if swapon --show 2>/dev/null | grep -q .; then
        log_ok "Swap уже настроен"
    else
        log_info "Swap не найден, создаю swap-файл 2G..."
        if fallocate -l 2G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none 2>/dev/null; then
            chmod 600 /swapfile
            mkswap /swapfile > /dev/null 2>&1
            swapon /swapfile
            grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
            log_ok "Swap-файл 2G создан и активирован"
        else
            log_warn "Не удалось создать swap-файл"
        fi
    fi
}

# ============================================================================
# ЧАСТЬ 2: УСТАНОВКА DOCKER (официальный метод)
# ============================================================================

install_docker() {
    log_step "DOCKER"
    
    if [[ "${STATE[docker_installed]}" == true ]]; then
        log_ok "Docker уже установлен: ${STATE[docker_version]}"
        
        # Проверяем запущен ли
        if ! systemctl is-active docker &>/dev/null; then
            log_info "Запускаю Docker..."
            systemctl start docker
            systemctl enable docker
        fi
        return
    fi
    
    log_info "Установка Docker (официальный метод)..."

    # Официальный метод установки из документации RemnaWave
    if ! curl -fsSL https://get.docker.com | sh; then
        log_error "get.docker.com installer завершился с ошибкой"
        exit 1
    fi

    # Запускаем
    systemctl enable docker || log_warn "systemctl enable docker вернул ошибку"
    systemctl start docker || true

    # Проверяем сначала бинарник
    if ! command -v docker &> /dev/null; then
        log_error "Не удалось установить Docker (бинарник отсутствует)!"
        exit 1
    fi

    # Проверяем что daemon реально запущен (главное условие для compose)
    sleep 2
    if ! systemctl is-active --quiet docker; then
        log_error "Docker daemon НЕ запустился (docker.service не active)"
        echo ""
        echo -e "${RED}--- systemctl status docker.service ---${NC}"
        systemctl status docker.service --no-pager -l || true
        echo ""
        echo -e "${RED}--- journalctl -xeu docker.service (хвост) ---${NC}"
        journalctl -xeu docker.service --no-pager 2>/dev/null | tail -50 || true
        echo ""
        echo -e "${YELLOW}Типовые причины:${NC}"
        echo "  • битый /etc/docker/daemon.json"
        echo "  • остатки старого containerd: /etc/containerd/config.toml"
        echo "  • конфликт iptables-nft / legacy"
        echo "  • остатки прежней инсталляции в /var/lib/docker"
        exit 1
    fi

    # Финальная sanity-проверка через сам docker CLI
    if ! docker info &>/dev/null; then
        log_error "docker info не работает — daemon недоступен через сокет"
        exit 1
    fi

    log_ok "Docker установлен и работает: $(docker --version)"
}

# ============================================================================
# ЧАСТЬ 3: УСТАНОВКА REMNAWAVE NODE
# ============================================================================

install_remnanode() {
    log_step "REMNAWAVE NODE"
    
    if [[ "$SKIP_NODE_INSTALL" == true ]]; then
        log_info "Пропуск установки RemnaWave Node"
        return
    fi
    
    # Создаём директорию (согласно документации)
    log_info "Создание директории $REMNANODE_DIR..."
    mkdir -p "$REMNANODE_DIR"
    cd "$REMNANODE_DIR"
    
    # Бэкап старого конфига если есть
    if [[ -f docker-compose.yml ]]; then
        cp docker-compose.yml "docker-compose.yml.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    # Удаляем старые .env файлы
    rm -f .env .env.* 2>/dev/null || true
    
    # Создаём docker-compose.yml с нашим портом
    log_info "Создание docker-compose.yml..."
    cat > docker-compose.yml << EOF
services:
  remnanode:
    container_name: remnanode
    hostname: remnanode
    image: remnawave/node:latest
    network_mode: host
    restart: always
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    environment:
      - NODE_PORT=${NEW_NODE_PORT}
      - SECRET_KEY="${SECRET_KEY}"
EOF
    
    log_ok "docker-compose.yml создан"
    
    # Запускаем (согласно документации)
    log_info "Запуск контейнера..."
    docker compose pull
    docker compose up -d
    
    sleep 3
    
    if docker ps | grep -q remnanode; then
        log_ok "RemnaWave Node запущен"
    else
        log_error "RemnaWave Node не запустился!"
        docker compose logs --tail 20
        exit 1
    fi
}

# ============================================================================
# ЧАСТЬ 4: НАСТРОЙКА БЕЗОПАСНОСТИ (SSH + UFW)
# ============================================================================

setup_security() {
    if [[ "$SKIP_SECURITY" == true ]]; then
        log_info "Пропуск настройки безопасности (--skip-security)"
        return
    fi
    
    log_step "НАСТРОЙКА БЕЗОПАСНОСТИ"
    
    # === UFW ===
    log_substep "UFW"
    
    if [[ "${STATE[ufw_installed]}" != true ]]; then
        log_info "Установка UFW..."
        apt-get update -qq
        apt-get install -y -qq ufw
        log_ok "UFW установлен"
    else
        log_ok "UFW уже установлен"
    fi
    
    # === SSH ===
    log_substep "SSH"
    
    # Проверяем текущий порт
    local current_ssh_port=$(grep -E "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    current_ssh_port=${current_ssh_port:-22}
    
    if [[ "$current_ssh_port" == "$NEW_SSH_PORT" ]]; then
        log_ok "SSH уже на порту $NEW_SSH_PORT"
    else
        log_info "Изменение SSH порта: $current_ssh_port → $NEW_SSH_PORT..."
        
        # Бэкап конфига
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)
        
        # Меняем порт
        if grep -q "^Port " /etc/ssh/sshd_config; then
            sed -i "s/^Port .*/Port $NEW_SSH_PORT/" /etc/ssh/sshd_config
        elif grep -q "^#Port " /etc/ssh/sshd_config; then
            sed -i "s/^#Port .*/Port $NEW_SSH_PORT/" /etc/ssh/sshd_config
        else
            echo "Port $NEW_SSH_PORT" >> /etc/ssh/sshd_config
        fi
        
        # КРИТИЧНО: Отключаем ssh.socket (Ubuntu 22.04+)
        if systemctl list-unit-files | grep -q "ssh.socket"; then
            log_info "Обнаружен ssh.socket (Ubuntu 22.04+), отключаю..."
            systemctl stop ssh.socket 2>/dev/null || true
            systemctl disable ssh.socket 2>/dev/null || true
            sleep 2
        fi
        
        # Определяем имя сервиса (ssh на Ubuntu, sshd на CentOS/RHEL)
        if [ -f /lib/systemd/system/ssh.service ] || systemctl cat ssh.service &>/dev/null; then
            SSH_SERVICE="ssh"
        elif [ -f /lib/systemd/system/sshd.service ] || systemctl cat sshd.service &>/dev/null; then
            SSH_SERVICE="sshd"
        else
            log_error "SSH сервис не найден (ни ssh.service, ни sshd.service)!"
            exit 1
        fi
        log_info "SSH сервис: ${SSH_SERVICE}.service"
        
        # Перезапускаем SSH
        systemctl stop $SSH_SERVICE 2>/dev/null || true
        sleep 3
        systemctl enable $SSH_SERVICE 2>/dev/null || true
        systemctl start $SSH_SERVICE
        sleep 2
        
        # Проверяем IPv4
        if ss -tlnp | grep -q "0.0.0.0:$NEW_SSH_PORT"; then
            log_ok "SSH слушает на 0.0.0.0:$NEW_SSH_PORT (IPv4)"
        elif ss -tlnp | grep -q "\[::\]:$NEW_SSH_PORT"; then
            log_warn "SSH только на IPv6, пробую перезапустить..."
            systemctl stop $SSH_SERVICE
            sleep 3
            systemctl start $SSH_SERVICE
            sleep 2
            
            if ! ss -tlnp | grep -q "0.0.0.0:$NEW_SSH_PORT"; then
                log_error "SSH слушает только на IPv6!"
                echo ""
                echo -e "${RED}КРИТИЧЕСКАЯ ОШИБКА: SSH только на IPv6${NC}"
                echo "Исправь вручную:"
                echo "  1. systemctl stop ssh.socket"
                echo "  2. systemctl disable ssh.socket"
                echo "  3. systemctl restart $SSH_SERVICE"
                exit 1
            fi
        fi
    fi
    
    # === UFW ПРАВИЛА ===
    log_substep "Правила UFW"
    
    log_info "Настройка правил UFW..."
    
    # Сбрасываем правила
    ufw --force reset
    
    # Политика по умолчанию
    ufw default deny incoming
    ufw default allow outgoing
    
    # SSH
    ufw allow $NEW_SSH_PORT/tcp comment 'SSH'
    
    # Node порт (через AWG)
    ufw allow from 10.10.0.0/24 to any port $NEW_NODE_PORT proto tcp comment 'RemnaWave via AWG'
    
    # Fallback: с IP панели напрямую
    ufw allow from $PANEL_IP to any port $NEW_NODE_PORT proto tcp comment 'RemnaWave Panel Direct'
    
    # VPN порты
    ufw allow $VPN_PORT/tcp comment 'VPN VLESS'
    if [[ -n "$EXTRA_VPN_PORT" ]]; then
        ufw allow $EXTRA_VPN_PORT/tcp comment 'VPN xHTTP'
    fi
    
    # Включаем UFW
    ufw --force enable
    
    # Удаляем IPv6 правила
    log_info "Удаление IPv6 правил..."
    for i in $(ufw status numbered | grep "(v6)" | awk -F'[][]' '{print $2}' | sort -rn); do
        ufw --force delete $i 2>/dev/null || true
    done
    
    log_ok "UFW настроен"
    
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  ВАЖНО: SSH порт изменён на ${NEW_SSH_PORT}${NC}"
    echo -e "${YELLOW}  Проверь подключение в НОВОЙ сессии!${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo ""
    
    if [[ "$INTERACTIVE" == true ]]; then
        read -p "SSH работает на порту $NEW_SSH_PORT? (yes для продолжения): " confirm
        if [[ "$confirm" != "yes" ]]; then
            log_warn "Откатываю изменения..."
            ufw disable
            exit 1
        fi
    fi
}

# ============================================================================
# ЧАСТЬ 5: УСТАНОВКА AMNEZIAWG
# ============================================================================

install_awg() {
    if [[ "$SKIP_AWG" == true ]]; then
        log_info "Пропуск установки AWG (--skip-awg)"
        return
    fi
    
    log_step "AMNEZIAWG"
    
    # Установка
    if [[ "${STATE[awg_installed]}" != true ]]; then
        log_info "Установка AmneziaWG..."
        
        # Прямой метод (обход проблемы с PPA)
        curl -fsSL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x57290828" \
            | gpg --dearmor -o /usr/share/keyrings/amnezia.gpg 2>/dev/null || true
        
        echo "deb [signed-by=/usr/share/keyrings/amnezia.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" \
            | tee /etc/apt/sources.list.d/amnezia.list > /dev/null
        
        apt-get update
        apt-get install -y linux-headers-$(uname -r) 2>/dev/null || true
        
        if ! apt-get install -y amneziawg amneziawg-tools 2>/dev/null; then
            log_warn "Стандартная установка не удалась, пробую DKMS..."
            apt-get install -y amneziawg-dkms amneziawg-tools 2>/dev/null || {
                log_error "Не удалось установить AmneziaWG"
                return
            }
        fi
        
        modprobe amneziawg 2>/dev/null || true
        log_ok "AmneziaWG установлен"
    else
        log_ok "AmneziaWG уже установлен"
        modprobe amneziawg 2>/dev/null || true
    fi
    
    # Конфигурация
    log_info "Настройка AWG клиента..."
    
    AWG_CONFIG_DIR="/etc/amnezia/amneziawg"
    mkdir -p "$AWG_CONFIG_DIR"
    cd "$AWG_CONFIG_DIR"
    
    # Ключи
    if [[ ! -f privatekey ]]; then
        awg genkey | tee privatekey | awg pubkey > publickey
        chmod 600 privatekey
        log_ok "Ключи сгенерированы"
    else
        log_ok "Ключи уже существуют"
    fi
    
    PRIVATE_KEY=$(cat privatekey)
    PUBLIC_KEY=$(cat publickey)
    
    # Конфиг
    cat > awg0.conf << EOF
[Interface]
Address = ${NODE_AWG_IP}/32
PrivateKey = $PRIVATE_KEY

Jc = 4
Jmin = 40
Jmax = 70
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = $PANEL_AWG_PUBKEY
Endpoint = ${PANEL_IP}:${PANEL_AWG_PORT}
AllowedIPs = 10.10.0.0/24
PersistentKeepalive = 25
EOF
    chmod 600 awg0.conf
    
    # Systemd сервис
    cat > /etc/systemd/system/awg-quick@.service << 'EOF'
[Unit]
Description=AmneziaWG via awg-quick(8) for %I
After=network-online.target nss-lookup.target
Wants=network-online.target nss-lookup.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/awg-quick up %i
ExecStop=/usr/bin/awg-quick down %i

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable awg-quick@awg0
    
    # Запуск
    awg-quick down awg0 2>/dev/null || true
    awg-quick up awg0
    
    log_ok "AmneziaWG настроен"
    
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo -e "  Публичный ключ ноды:"
    echo -e "  ${GREEN}$PUBLIC_KEY${NC}"
    echo ""
    echo -e "  ${RED}На панели выполни:${NC}"
    echo -e "  ${CYAN}./add-peer.sh $NODE_NAME $PUBLIC_KEY $NODE_AWG_IP${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Проверка связи
    sleep 3
    if ping -c 2 -W 3 10.10.0.1 &>/dev/null; then
        log_ok "Связь с панелью установлена"
    else
        log_warn "Нет связи с панелью. Добавь пир на панели!"
    fi
}

# ============================================================================
# ЧАСТЬ 6: УСТАНОВКА PROMTAIL
# ============================================================================

install_promtail() {
    if [[ "$SKIP_PROMTAIL" == true ]]; then
        log_info "Пропуск установки Promtail (--skip-promtail)"
        return
    fi
    
    # Проверка: уже установлен?
    if [[ "${STATE[promtail_running]}" == true ]]; then
        log_info "Promtail уже установлен и запущен"
        return
    fi
    
    log_step "PROMTAIL"
    
    # Проверка AWG
    if ! ping -c 1 -W 3 10.10.0.1 &>/dev/null; then
        log_warn "AWG туннель не работает, Promtail не сможет отправлять логи"
        log_warn "Сначала добавь пир на панели, затем перезапусти Promtail"
    fi
    
    # Logrotate
    if ! command -v logrotate &>/dev/null; then
        apt-get install -y logrotate
    fi
    
    cd "$REMNANODE_DIR"
    
    # docker-compose.override.yml
    log_info "Создание docker-compose.override.yml..."
    cat > docker-compose.override.yml << 'EOF'
services:
  remnanode:
    volumes:
      - xray-logs:/var/log/supervisor

  promtail:
    image: grafana/promtail:3.0.0
    container_name: promtail
    restart: always
    network_mode: host
    volumes:
      - xray-logs:/var/log/xray:ro
      - ./promtail-config.yaml:/etc/promtail/config.yaml
    command: -config.file=/etc/promtail/config.yaml

volumes:
  xray-logs:
EOF
    
    # promtail-config.yaml
    log_info "Создание promtail-config.yaml..."
    cat > promtail-config.yaml << EOF
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: ${VICTORIA_URL}

scrape_configs:
  - job_name: xray
    static_configs:
      - targets:
          - localhost
        labels:
          job: xray
          node: ${NODE_NAME}
          __path__: /var/log/xray/xray.out.log

  - job_name: xray-errors
    static_configs:
      - targets:
          - localhost
        labels:
          job: xray-errors
          node: ${NODE_NAME}
          __path__: /var/log/xray/xray.err.log
EOF
    
    # Logrotate конфиг
    log_info "Настройка ротации логов..."
    cat > /etc/logrotate.d/xray-logs << 'EOF'
/var/lib/docker/volumes/*xray-logs*/_data/*.log {
    daily
    rotate 7
    size 50M
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
    
    # Перезапуск
    log_info "Перезапуск контейнеров..."
    docker compose down
    docker compose up -d
    
    sleep 5
    
    if docker ps | grep -q promtail; then
        log_ok "Promtail запущен"
    else
        log_warn "Promtail не запустился"
    fi
}

# ============================================================================
# ФИНАЛЬНЫЙ ОТЧЁТ
# ============================================================================

final_report() {
    log_step "ФИНАЛЬНЫЙ ОТЧЁТ"
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              УСТАНОВКА ЗАВЕРШЕНА                               ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Повторная диагностика
    echo -e "${BOLD}Текущее состояние системы:${NC}"
    echo ""
    
    # Система
    echo -e "${CYAN}Система:${NC}"
    echo -e "  ОС:            ${STATE[os_name]} ${STATE[os_version]}"
    echo -e "  Ядро:          ${STATE[kernel_version]}"
    echo -e "  CPU/RAM:       ${STATE[cpu_cores]} cores / ${STATE[ram_total]}"
    echo -e "  IP:            ${STATE[public_ip]}"
    echo ""
    
    # Docker
    echo -e "${CYAN}Docker:${NC}"
    local docker_ver=$(docker --version 2>/dev/null | grep -oP 'Docker version \K[0-9.]+' || echo "не установлен")
    echo -e "  Версия:        $docker_ver"
    if systemctl is-active docker &>/dev/null; then
        echo -e "  Статус:        ${GREEN}✓ запущен${NC}"
    else
        echo -e "  Статус:        ${RED}✗ не запущен${NC}"
    fi
    echo ""
    
    # RemnaWave Node
    echo -e "${CYAN}RemnaWave Node:${NC}"
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^remnanode$"; then
        echo -e "  Статус:        ${GREEN}✓ запущен${NC}"
        echo -e "  Порт:          $NEW_NODE_PORT"
    else
        echo -e "  Статус:        ${RED}✗ не запущен${NC}"
    fi
    echo ""
    
    # Безопасность
    echo -e "${CYAN}Безопасность:${NC}"
    local ssh_port=$(grep -E "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    ssh_port=${ssh_port:-22}
    echo -e "  SSH порт:      $ssh_port"
    if ufw status | grep -q "Status: active"; then
        echo -e "  UFW:           ${GREEN}✓ активен${NC}"
    else
        echo -e "  UFW:           ${YELLOW}⚠ не активен${NC}"
    fi
    echo ""
    
    # AWG
    if [[ "$SKIP_AWG" != true ]]; then
        echo -e "${CYAN}AmneziaWG:${NC}"
        if ip link show awg0 &>/dev/null; then
            local awg_ip=$(ip addr show awg0 2>/dev/null | grep -oP 'inet \K[0-9.]+' || echo "?")
            echo -e "  Туннель:       ${GREEN}✓ активен ($awg_ip)${NC}"
            
            if ping -c 1 -W 2 10.10.0.1 &>/dev/null; then
                echo -e "  Связь с панелью: ${GREEN}✓ есть${NC}"
            else
                echo -e "  Связь с панелью: ${YELLOW}⚠ нет${NC}"
            fi
            
            local pubkey=$(cat /etc/amnezia/amneziawg/publickey 2>/dev/null || echo "не найден")
            echo -e "  Публичный ключ: ${CYAN}$pubkey${NC}"
        else
            echo -e "  Туннель:       ${YELLOW}⚠ не активен${NC}"
        fi
        echo ""
    fi
    
    # Promtail
    if [[ "$SKIP_PROMTAIL" != true ]]; then
        echo -e "${CYAN}Promtail:${NC}"
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^promtail$"; then
            echo -e "  Статус:        ${GREEN}✓ запущен${NC}"
        else
            echo -e "  Статус:        ${YELLOW}⚠ не запущен${NC}"
        fi
        echo ""
    fi
    
    # Оптимизация
    echo -e "${CYAN}Оптимизация:${NC}"
    local cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "?")
    echo -e "  BBR:           $([[ "$cc" == "bbr" ]] && echo -e "${GREEN}✓${NC}" || echo -e "${YELLOW}✗${NC}") ($cc)"
    local rmem=$(sysctl -n net.core.rmem_max 2>/dev/null || echo "?")
    echo -e "  TCP buffers:   $([[ "$rmem" -ge 16777216 ]] && echo -e "${GREEN}✓${NC}" || echo -e "${YELLOW}✗${NC}") (rmem_max=$rmem)"
    echo ""
    
    # Следующие шаги
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  СЛЕДУЮЩИЕ ШАГИ:${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  1. Проверь SSH на порту $NEW_SSH_PORT:"
    echo -e "     ${CYAN}ssh -p $NEW_SSH_PORT root@${STATE[public_ip]}${NC}"
    echo ""
    
    if [[ "$SKIP_AWG" != true ]] && [[ -f /etc/amnezia/amneziawg/publickey ]]; then
        local pubkey=$(cat /etc/amnezia/amneziawg/publickey)
        echo "  2. На ПАНЕЛИ добавь пир:"
        echo -e "     ${CYAN}./add-peer.sh $NODE_NAME $pubkey $NODE_AWG_IP${NC}"
        echo ""
    fi
    
    echo "  3. В RemnaWave Panel измени:"
    echo -e "     Адрес ноды: ${GREEN}$NODE_AWG_IP${NC}"
    echo -e "     Порт ноды:  ${GREEN}$NEW_NODE_PORT${NC}"
    echo ""
    echo -e "${GREEN}Готово!${NC}"
    echo ""
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    parse_args "$@"
    show_header
    check_root
    
    # Диагностика
    run_diagnostics
    
    # Только диагностика?
    if [[ "$DIAGNOSTIC_ONLY" == true ]]; then
        echo ""
        log_info "Режим диагностики завершён"
        exit 0
    fi
    
    # Сбор информации
    collect_info
    
    # Установка
    optimize_system
    install_docker
    install_remnanode
    setup_security
    install_awg
    install_promtail
    
    # Финальный отчёт
    final_report
}

main "$@"
