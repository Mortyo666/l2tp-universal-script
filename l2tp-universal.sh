#!/usr/bin/env bash
# Universal L2TP installer/rollback with robust stdin/args handling
# Author: Mortyo666 (updated by Comet Assistant)
# Commit: Универсально совместимый запуск для всех Linux, авто-меню независимо от способа вызова

set -euo pipefail
NC="\033[0m"; RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"; BLUE="\033[0;34m"
DATE_TAG="$(date +%Y%m%d-%H%M%S)"
BACKUP_ROOT="/root/l2tp-universal-backup-${DATE_TAG}"
BACKUP_BASE="/root"
LAST_LINK="/root/l2tp-universal-backup-latest"
OUT_FILE="/root/l2tp-clients-${DATE_TAG}.txt"
CONF_FILES=(
  "/etc/xl2tpd/xl2tpd.conf"
  "/etc/ipsec.conf"
  "/etc/ipsec.secrets"
  "/etc/ppp/options.xl2tpd"
  "/etc/ppp/chap-secrets"
  "/etc/sysctl.conf"
)
SERVICES=(ipsec xl2tpd)
SYSCTL_KEYS=(
  "net.ipv4.ip_forward"
  "net.ipv4.conf.all.accept_redirects"
  "net.ipv4.conf.all.send_redirects"
)
log(){ echo -e "${BLUE}[*]${NC} $*"; }
warn(){ echo -e "${YELLOW}[!]${NC} $*"; }
err(){ echo -e "${RED}[x]${NC} $*" 1>&2; }
success(){ echo -e "${GREEN}[✓]${NC} $*"; }
require_root(){ if command -v id >/dev/null 2>&1; then [ "$(id -u)" = 0 ] || { err "Run as root"; exit 1; }; else [ "${EUID:-$(sh -c 'echo ${EUID:-}' 2>/dev/null)}" = 0 ] || { err "Run as root"; exit 1; }; fi; }
get_iface(){ ip route get 1.1.1.1 2>/dev/null | awk '/ dev / {for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}' || true; }
backup_all(){
  mkdir -p "${BACKUP_ROOT}"; log "Создание бэкапа в ${BACKUP_ROOT}"
  for f in "${CONF_FILES[@]}"; do
    if [ -f "$f" ]; then mkdir -p "${BACKUP_ROOT}$(dirname "$f")"; cp -a "$f" "${BACKUP_ROOT}$f"; else mkdir -p "${BACKUP_ROOT}$(dirname "$f")"; : > "${BACKUP_ROOT}$f.absent"; fi
  done
  mkdir -p "${BACKUP_ROOT}/iptables"; iptables-save > "${BACKUP_ROOT}/iptables/iptables.save" 2>/dev/null || true; ip6tables-save > "${BACKUP_ROOT}/iptables/ip6tables.save" 2>/dev/null || true
  sysctl -a 2>/dev/null > "${BACKUP_ROOT}/sysctl-all.txt" || true
  mkdir -p "${BACKUP_ROOT}/systemd"; for s in "${SERVICES[@]}"; do systemctl is-enabled "$s" >/dev/null 2>&1 && echo enabled > "${BACKUP_ROOT}/systemd/${s}.enabled" || echo disabled > "${BACKUP_ROOT}/systemd/${s}.enabled"; systemctl is-active "$s" >/dev/null 2>&1 && echo active > "${BACKUP_ROOT}/systemd/${s}.active" || echo inactive > "${BACKUP_ROOT}/systemd/${s}.active"; done
  ln -sfn "${BACKUP_ROOT}" "${LAST_LINK}"; success "Бэкап создан: ${BACKUP_ROOT} (latest -> ${LAST_LINK})"
}
restore_from_backup(){ local src="${1:-}"; [ -n "$src" ] && [ -d "$src" ] || { err "Неверный путь бэкапа: $src"; exit 1; }; log "Откат из бэкапа: $src";
  for f in "${CONF_FILES[@]}"; do if [ -f "${src}$f.absent" ]; then [ -e "$f" ] && rm -f "$f"; else if [ -f "${src}$f" ]; then mkdir -p "$(dirname "$f")"; cp -a "${src}$f" "$f"; fi; fi; done
  [ -f "${src}/iptables/iptables.save" ] && iptables-restore < "${src}/iptables/iptables.save" || true
  [ -f "${src}/iptables/ip6tables.save" ] && ip6tables-restore < "${src}/iptables/ip6tables.save" || true
  for k in "${SYSCTL_KEYS[@]}"; do if grep -q "^${k}=" "${src}/sysctl-all.txt" 2>/dev/null || grep -q "^${k} = " "${src}/sysctl-all.txt" 2>/dev/null; then v=$(grep -m1 -E "^${k}( = |=)" "${src}/sysctl-all.txt" | awk -F' = ' '{print $2}'); [ -n "${v:-}" ] && sysctl -w "${k}=${v}" >/dev/null 2>&1 || true; fi; done
  for s in "${SERVICES[@]}"; do if [ -f "${src}/systemd/${s}.enabled" ]; then if grep -q enabled "${src}/systemd/${s}.enabled"; then systemctl enable "$s" >/dev/null 2>&1 || true; else systemctl disable "$s" >/dev/null 2>&1 || true; fi; fi; done
  for s in "${SERVICES[@]}"; do if [ -f "${src}/systemd/${s}.active" ]; then if grep -q active "${src}/systemd/${s}.active"; then systemctl restart "$s" >/dev/null 2>&1 || true; else systemctl stop "$s" >/dev/null 2>&1 || true; fi; fi; done
  success "Откат завершён"; }
print_connection_info(){ local OUT_IPS_STR="${OUTGOING_IPS:-}"; {
  echo "======== L2TP Connection Information ========"; echo "Дата: ${DATE_TAG}"; echo "Конфиг файлы: ${CONF_FILES[*]}"; echo
  if [ -n "$OUT_IPS_STR" ]; then echo "Пул исходящих IP: $OUT_IPS_STR"; else echo "Пул исходящих IP: не задан (используется SNAT на интерфейсе)"; fi; echo
  echo "Клиенты (OUTGOING_IP | USERNAME | PASSWORD | INTERNAL_IP)"; echo "----------------------------------------------------------"
  if [ -s /etc/ppp/chap-secrets ]; then local idx=0; read -r -a OUT_IPS_ARR <<<"$OUT_IPS_STR"; while IFS=$'\t ' read -r user server pass ip; do [ -z "${user:-}" ] && continue; case "$user" in \#*) continue ;; esac; if [ ${#OUT_IPS_ARR[@]} -gt 0 ]; then [ $idx -lt ${#OUT_IPS_ARR[@]} ] && outgoing="${OUT_IPS_ARR[$idx]}" || outgoing="${OUT_IPS_ARR[0]}"; else outgoing="assigned-on-connect"; fi; internal="${ip:-assigned-on-connect}"; echo "${outgoing} | ${user} | ${pass} | ${internal}"; idx=$((idx+1)); done < /etc/ppp/chap-secrets; else echo "Нет клиентов: файл /etc/ppp/chap-secrets пуст или отсутствует"; fi; echo "----------------------------------------------------------"; echo "Файл с данными: ${OUT_FILE}"; } | tee "${OUT_FILE}"; }
install_l2tp(){ require_root; backup_all; log "Установка пакетов";
  if command -v apt >/dev/null 2>&1; then export DEBIAN_FRONTEND=noninteractive; apt update -y && apt install -y strongswan xl2tpd ppp || true;
  elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then PKG_MGR=""; command -v dnf >/dev/null 2>&1 && PKG_MGR=dnf || PKG_MGR=yum; ${PKG_MGR} -y install epel-release || true; ${PKG_MGR} -y install strongswan xl2tpd ppp || ${PKG_MGR} -y install libreswan xl2tpd ppp || true;
  else warn "Неизвестный пакетный менеджер — пропуск установки пакетов"; fi
  log "Конфигурирование"; mkdir -p /etc/xl2tpd /etc/ppp; : > /etc/xl2tpd/xl2tpd.conf; : > /etc/ipsec.conf; : > /etc/ipsec.secrets; : > /etc/ppp/options.xl2tpd; : > /etc/ppp/chap-secrets
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
  sysctl -w net.ipv4.ip_forward=1 >/dev/null || true
  sysctl -w net.ipv4.conf.all.accept_redirects=0 >/dev/null || true
  sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null || true
  local IFACE; IFACE="${IFACE_OVERRIDE:-$(get_iface)}"; if [ -n "${IFACE:-}" ]; then iptables -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE; else warn "Не удалось определить интерфейс для SNAT"; fi
  systemctl enable ipsec xl2tpd >/dev/null 2>&1 || true; systemctl restart ipsec xl2tpd >/dev/null 2>&1 || true
  success "Установка завершена. Данные клиентов будут сохранены в ${OUT_FILE}"; print_connection_info; }
rollback_menu(){ require_root; local choose; log "Поиск доступных бэкапов в ${BACKUP_BASE}"; mapfile -t backups < <(ls -1d ${BACKUP_BASE}/l2tp-universal-backup-* 2>/dev/null | sort); [ ${#backups[@]} -gt 0 ] || { err "Бэкапы не найдены"; exit 1; }; echo "Доступные бэкапы:"; local i=1; for b in "${backups[@]}"; do echo "  $i) $b"; i=$((i+1)); done; read -rp "Введите номер бэкапа (или Enter для последнего): " choose || true; local sel; if [ -z "${choose:-}" ]; then sel="${backups[-1]}"; else echo "$choose" | grep -Eq '^[0-9]+$' && [ "$choose" -ge 1 ] && [ "$choose" -le ${#backups[@]} ] || { err "Неверный выбор"; exit 1; }; sel="${backups[$((choose-1))]}"; fi; restore_from_backup "$sel"; }
main_menu(){ echo "================ L2TP Universal ================="; echo "1) Установка L2TP"; echo "2) Откат (Rollback)"; echo "q) Выход"; echo "-----------------------------------------------"; }
should_auto_menu(){ case "${1:-}" in --install|--rollback|--help|-h) return 1;; esac; if [ "${BASH_SOURCE[0]:-x}" != "$0" ] 2>/dev/null; then return 1; fi; return 0; }
print_help(){ cat <<'HLP'
Usage:
  bash l2tp-universal.sh --install        Install L2TP (with backup)
  bash l2tp-universal.sh --rollback       Rollback to a selected backup
  bash l2tp-universal.sh                  Start interactive menu (any invocation)

Environment variables:
  OUTGOING_IPS="1.2.3.4 5.6.7.8"   Assign outgoing IP pool mapping in info output
  IFACE_OVERRIDE=eth0               Override detected egress interface for SNAT

Universal run examples (works on Ubuntu/CentOS/any bash):
  # Guaranteed way (download, chmod, run)
  curl -fsSL https://raw.githubusercontent.com/Mortyo666/l2tp-universal-script/refs/heads/main/l2tp-universal.sh -o l2tp-universal.sh \
    && chmod +x l2tp-universal.sh \
    && sudo bash ./l2tp-universal.sh

  # One-liner via process substitution (auto menu even without TTY stdin)
  bash <(curl -fsSL https://raw.githubusercontent.com/Mortyo666/l2tp-universal-script/refs/heads/main/l2tp-universal.sh)

  # Pipe fallback (still auto-menu):
  curl -fsSL https://raw.githubusercontent.com/Mortyo666/l2tp-universal-script/refs/heads/main/l2tp-universal.sh | sudo bash
HLP
}

main(){
  # Explicit argument handling
  case "${1:-}" in
    --install) install_l2tp; return;;
    --rollback) rollback_menu; return;;
    --help|-h) print_help; return;;
  esac
  # Auto menu regardless of stdin/tty when no args
  if should_auto_menu "${1:-}"; then
    while true; do
      main_menu
      # read works even without TTY when input is redirected; fallback to default action if it fails
      if ! read -rp "Выберите действие: " ans; then ans=1; fi
      case "$ans" in
        1) install_l2tp; break ;;
        2) rollback_menu; break ;;
        q|Q) exit 0 ;;
        *) echo "Неверный выбор" ;;
      esac
    done
  fi
}

# Entry point
main "${1:-}"
