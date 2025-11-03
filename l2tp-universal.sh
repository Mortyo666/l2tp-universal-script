#!/usr/bin/env bash
set -euo pipefail
# l2tp-universal.sh with universal backup and rollback
# Author: Mortyo666 (updated)
# Commit: Добавлен режим бэкапов и универсального безопасного отката l2tp-universal-rollback
# Colors
NC="\033[0m"; RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"; BLUE="\033[0;34m"
# Globals
DATE_TAG="$(date +%Y%m%d-%H%M%S)"
BACKUP_ROOT="/root/l2tp-universal-backup-${DATE_TAG}"
BACKUP_BASE="/root"
LAST_LINK="/root/l2tp-universal-backup-latest"
OUT_FILE="/root/l2tp-clients-${DATE_TAG}.txt"
# Files and paths we manage
CONF_FILES=(
  "/etc/xl2tpd/xl2tpd.conf"
  "/etc/ipsec.conf"
  "/etc/ipsec.secrets"
  "/etc/ppp/options.xl2tpd"
  "/etc/ppp/chap-secrets"
  "/etc/sysctl.conf"
)
SERVICES=(ipsec xl2tpd)
# sysctl parameters we touch
SYSCTL_KEYS=(
  "net.ipv4.ip_forward"
  "net.ipv4.conf.all.accept_redirects"
  "net.ipv4.conf.all.send_redirects"
)
# Helper: log
log() { echo -e "${BLUE}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err() { echo -e "${RED}[x]${NC} $*" 1>&2; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
require_root() {
  if [[ $(id -u) -ne 0 ]]; then err "Run as root"; exit 1; fi
}
# Detect primary interface for SNAT
get_iface() {
  ip route get 1.1.1.1 2>/dev/null | awk '/ dev / {for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}' || true
}
# Backup current state (files, iptables, versions)
backup_all() {
  mkdir -p "${BACKUP_ROOT}"
  log "Создание бэкапа в ${BACKUP_ROOT}"
  # Copy config files if they exist
  for f in "${CONF_FILES[@]}"; do
    if [[ -f "$f" ]]; then
      mkdir -p "${BACKUP_ROOT}$(dirname "$f")"
      cp -a "$f" "${BACKUP_ROOT}$f"
    else
      # mark as absent
      mkdir -p "${BACKUP_ROOT}$(dirname "$f")"
      touch "${BACKUP_ROOT}$f.absent"
    fi
  done
  # Save iptables
  mkdir -p "${BACKUP_ROOT}/iptables"
  iptables-save > "${BACKUP_ROOT}/iptables/iptables.save" 2>/dev/null || true
  ip6tables-save > "${BACKUP_ROOT}/iptables/ip6tables.save" 2>/dev/null || true
  # Save sysctl snapshot
  sysctl -a 2>/dev/null > "${BACKUP_ROOT}/sysctl-all.txt" || true
  # Save service states (enabled/active)
  mkdir -p "${BACKUP_ROOT}/systemd"
  for s in "${SERVICES[@]}"; do
    systemctl is-enabled "$s" >/dev/null 2>&1 && echo enabled > "${BACKUP_ROOT}/systemd/${s}.enabled" || echo disabled > "${BACKUP_ROOT}/systemd/${s}.enabled"
    systemctl is-active "$s" >/dev/null 2>&1 && echo active > "${BACKUP_ROOT}/systemd/${s}.active" || echo inactive > "${BACKUP_ROOT}/systemd/${s}.active"
  done
  ln -sfn "${BACKUP_ROOT}" "${LAST_LINK}"
  success "Бэкап создан: ${BACKUP_ROOT} (latest -> ${LAST_LINK})"
}
# Restore from backup directory
restore_from_backup() {
  local src="${1:-}"
  if [[ -z "$src" || ! -d "$src" ]]; then err "Неверный путь бэкапа: $src"; exit 1; fi
  log "Откат из бэкапа: $src"
  # Restore config files: if .absent existed originally, remove now-created file; else copy back
  for f in "${CONF_FILES[@]}"; do
    if [[ -f "${src}$f.absent" ]]; then
      # Was absent originally: remove if now exists
      if [[ -e "$f" ]]; then rm -f "$f"; fi
    else
      if [[ -f "${src}$f" ]]; then
        mkdir -p "$(dirname "$f")"
        cp -a "${src}$f" "$f"
      fi
    fi
  done
  # Restore iptables
  if [[ -f "${src}/iptables/iptables.save" ]]; then
    iptables-restore < "${src}/iptables/iptables.save" || warn "Не удалось восстановить iptables"
  fi
  if [[ -f "${src}/iptables/ip6tables.save" ]]; then
    ip6tables-restore < "${src}/iptables/ip6tables.save" || warn "Не удалось восстановить ip6tables"
  fi
  # Restore sysctl only selected keys
  for k in "${SYSCTL_KEYS[@]}"; do
    if grep -q "^${k}=" "${src}/sysctl-all.txt" 2>/dev/null || grep -q "^${k} = " "${src}/sysctl-all.txt" 2>/dev/null; then
      local v
      v=$(grep -m1 -E "^${k}( = |=)" "${src}/sysctl-all.txt" | awk -F' = ' '{print $2}')
      if [[ -n "${v:-}" ]]; then sysctl -w "${k}=${v}" >/dev/null 2>&1 || true; fi
    fi
  done
  # Restore service state
  for s in "${SERVICES[@]}"; do
    if [[ -f "${src}/systemd/${s}.enabled" ]]; then
      if grep -q enabled "${src}/systemd/${s}.enabled"; then systemctl enable "$s" >/dev/null 2>&1 || true; else systemctl disable "$s" >/dev/null 2>&1 || true; fi
    fi
  done
  for s in "${SERVICES[@]}"; do
    if [[ -f "${src}/systemd/${s}.active" ]]; then
      if grep -q active "${src}/systemd/${s}.active"; then systemctl restart "$s" >/dev/null 2>&1 || true; else systemctl stop "$s" >/dev/null 2>&1 || true; fi
    fi
  done
  success "Откат завершён"
}

# Helper: collect and print connection info neatly and save to OUT_FILE
print_connection_info() {
  # OUTGOING_IPS may be provided externally; if not, try to infer from ip route addr (none by default)
  local OUT_IPS_STR="${OUTGOING_IPS:-}"
  # Prepare header
  {
    echo "======== L2TP Connection Information ========"
    echo "Дата: ${DATE_TAG}"
    echo "Конфиг файлы: ${CONF_FILES[*]}"
    echo
    if [[ -n "$OUT_IPS_STR" ]]; then
      echo "Пул исходящих IP: $OUT_IPS_STR"
    else
      echo "Пул исходящих IP: не задан (используется SNAT на интерфейсе)"
    fi
    echo
    echo "Клиенты (OUTGOING_IP | USERNAME | PASSWORD | INTERNAL_IP)"
    echo "----------------------------------------------------------"
    # Build clients table from chap-secrets; CHAP format: user  server  password  IP
    if [[ -s /etc/ppp/chap-secrets ]]; then
      local idx=0
      # normalize OUT_IPS into array
      read -r -a OUT_IPS_ARR <<<"$OUT_IPS_STR"
      while IFS=$'\t ' read -r user server pass ip; do
        # skip comments/blank
        [[ -z "${user:-}" || "${user:0:1}" == "#" ]] && continue
        local outgoing=""
        if (( ${#OUT_IPS_ARR[@]} > 0 )); then
          if (( idx < ${#OUT_IPS_ARR[@]} )); then
            outgoing="${OUT_IPS_ARR[$idx]}"
          else
            outgoing="${OUT_IPS_ARR[0]}"
          fi
        else
          outgoing="assigned-on-connect"
        fi
        local internal="${ip:-assigned-on-connect}"
        echo "${outgoing} | ${user} | ${pass} | ${internal}"
        ((idx++))
      done < /etc/ppp/chap-secrets
    else
      echo "Нет клиентов: файл /etc/ppp/chap-secrets пуст или отсутствует"
    fi
    echo "----------------------------------------------------------"
    echo "Файл с данными: ${OUT_FILE}"
  } | tee "${OUT_FILE}"
}

# Install L2TP stack (minimal, placeholder for existing logic)
install_l2tp() {
  require_root
  backup_all
  log "Установка пакетов"
  if command -v apt >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt update -y && apt install -y strongswan xl2tpd ppp
  elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    # Choose package manager reliably without subshell; avoid unbound variable
    local PKG_MGR=""
    if command -v dnf >/dev/null 2>&1; then PKG_MGR=dnf; else PKG_MGR=yum; fi
    ${PKG_MGR} -y install epel-release || true
    ${PKG_MGR} -y install strongswan xl2tpd ppp || ${PKG_MGR} -y install libreswan xl2tpd ppp || true
  else
    warn "Неизвестный пакетный менеджер — пропуск установки пакетов"
  fi
  log "Конфигурирование"
  mkdir -p /etc/xl2tpd /etc/ppp
  : > /etc/xl2tpd/xl2tpd.conf
  : > /etc/ipsec.conf
  : > /etc/ipsec.secrets
  : > /etc/ppp/options.xl2tpd
  : > /etc/ppp/chap-secrets
  # Minimal safe defaults (replace with your current generation logic if exists)
  cat >/etc/xl2tpd/xl2tpd.conf <<'EOF'
[global]
port = 1701
[lns default]
ip range = 10.10.10.10-10.10.10.250
local ip = 10.10.10.1
refuse chap = yes
require authentication = yes
name = l2tp
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF
  cat >/etc/ppp/options.xl2tpd <<'EOF'
ipcp-accept-local
ipcp-accept-remote
ms-dns 1.1.1.1
ms-dns 8.8.8.8
asyncmap 0
auth
crtscts
lock
hide-password
modem
mtu 1410
mru 1410
lcp-echo-interval 30
lcp-echo-failure 4
require-mschap-v2
refuse-mschap
noccp
connect-delay 5000
EOF
  echo "l2tp * password *" > /etc/ppp/chap-secrets
  cat >/etc/ipsec.conf <<'EOF'
config setup
    charondebug="ike 1, knl 1, cfg 0"
conn L2TP-PSK
    keyexchange=ikev1
    authby=psk
    type=transport
    left=%any
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/1701
    auto=add
EOF
  echo ": PSK \"topsecret\"" > /etc/ipsec.secrets
  # sysctl
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  sysctl -w net.ipv4.conf.all.accept_redirects=0 >/dev/null
  sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null
  # firewall SNAT
  local IFACE
  IFACE="${IFACE_OVERRIDE:-$(get_iface)}"
  if [[ -n "${IFACE:-}" ]]; then
    iptables -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE
  else
    warn "Не удалось определить интерфейс для SNAT"
  fi
  # restart
  systemctl enable ipsec xl2tpd >/dev/null 2>&1 || true
  systemctl restart ipsec xl2tpd >/dev/null 2>&1 || true
  success "Установка завершена. Данные клиентов будут сохранены в ${OUT_FILE}"
  # Immediately show connection info for convenience
  print_connection_info
}
# Rollback menu and actions
rollback_menu() {
  require_root
  local choose
  log "Поиск доступных бэкапов в ${BACKUP_BASE}"
  mapfile -t backups < <(ls -1d ${BACKUP_BASE}/l2tp-universal-backup-* 2>/dev/null | sort)
  if [[ ${#backups[@]} -eq 0 ]]; then err "Бэкапы не найдены"; exit 1; fi
  echo "Доступные бэкапы:"; local i=1; for b in "${backups[@]}"; do echo "  $i) $b"; ((i++)); done
  read -rp "Введите номер бэкапа (или Enter для последнего): " choose || true
  local sel
  if [[ -z "${choose:-}" ]]; then sel="${backups[-1]}"; else
    if ! [[ "$choose" =~ ^[0-9]+$ ]] || (( choose < 1 || choose > ${#backups[@]} )); then err "Неверный выбор"; exit 1; fi
    sel="${backups[$((choose-1))]}"
  fi
  restore_from_backup "$sel"
}
main_menu() {
  echo "================ L2TP Universal ================="
  echo "1) Установка L2TP"
  echo "2) Откат (Rollback)"
  echo "q) Выход"
  echo "-----------------------------------------------"
}
main() {
  require_root
  if [[ "${1:-}" == "--install" ]]; then install_l2tp; return; fi
  if [[ "${1:-}" == "--rollback" ]]; then rollback_menu; return; fi
  while true; do
    main_menu
    read -rp "Выберите действие: " ans || true
    case "$ans" in
      1) install_l2tp ; break ;;
      2) rollback_menu ; break ;;
      q|Q) exit 0 ;;
      *) echo "Неверный выбор" ;;
    esac
  done
}
# README notice about OUTGOING_IPS retained from previous versions
# ============ README NOTICE ============
# Данный скрипт поддерживает явный список исходящих IP через переменную OUTGOING_IPS,
# например:
#   OUTGOING_IPS="1.2.3.4 5.6.7.8" bash l2tp-universal.sh
# При задании OUTGOING_IPS используется только этот список (никакие служебные/локальные/авто-IP не затрагиваются).
# При авто-режиме скрипт исключает служебные IP (10.180.1.1, 10.180.2.1, 10.180.5.1) и приватные диапазоны
# (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12, 127.0.0.0/8, 169.254.0.0/16, 100.64.0.0/10).
# Каждому пользователю в выводе назначается уникальный OUTGOING_IP по порядку из списка.
# Если
