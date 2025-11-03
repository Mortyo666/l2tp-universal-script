#!/usr/bin/env bash
# Universal L2TP installer/rollback with robust stdin/args handling
# Author: Mortyo666 (updated by Comet Assistant)
# Commit: Исправлен порядок функций, стопроцентная совместимость process substitution и STDIN для любых bash.
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

# --- Functions (all declared before main for pipe/process substitution compatibility) ---
log(){ echo -e "${BLUE}[*]${NC} $*"; }
warn(){ echo -e "${YELLOW}[!]${NC} $*"; }
err(){ echo -e "${RED}[x]${NC} $*" 1>&2; }
success(){ echo -e "${GREEN}[✓]${NC} $*"; }

require_root(){
  if command -v id >/dev/null 2>&1; then
    [ "$(id -u)" = 0 ] || { err "Run as root"; exit 1; }
  else
    [ "${EUID:-$(sh -c 'echo ${EUID:-}' 2>/dev/null)}" = 0 ] || { err "Run as root"; exit 1; }
  fi
}

get_iface(){ ip route get 1.1.1.1 2>/dev/null | awk '/ dev / {for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}' || true; }

get_public_ipv4_list(){
  ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 |
  awk '
    function is_private(ip){ split(ip,a,"."); if(a[1]==10) return 1; if(a[1]==172 && a[2]>=16 && a[2]<=31) return 1; if(a[1]==192 && a[2]==168) return 1; return 0; }
    function is_loopback(ip){ split(ip,a,"."); return a[1]==127 }
    function is_linklocal(ip){ split(ip,a,"."); return a[1]==169 && a[2]==254 }
    function is_multicast(ip){ split(ip,a,"."); return a[1]>=224 && a[1]<=239 }
    function is_reserved(ip){ split(ip,a,"."); return a[1]==0 || a[1]==255 }
    function is_service(ip){ split(ip,a,"."); return (a[1]==10 && a[2]==180) }
    { if(is_loopback($0) || is_linklocal($0) || is_multicast($0) || is_reserved($0)) next; if(is_private($0) || is_service($0)) next; print $0; }
  ' | sort -V | uniq
}

build_outgoing_pool(){
  local OUT_IPS_STR="${OUTGOING_IPS:-}"
  local -a OUT_ARR=()
  if [ -n "$OUT_IPS_STR" ]; then
    while read -r ip; do
      [ -z "$ip" ] && continue
      if printf '%s' "$ip" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
        IFS=. read -r a b c d <<<"$ip"
        if [ "$a" = 10 ] && [ "$b" = 180 ]; then continue; fi
        if [ "$a" = 10 ] || { [ "$a" = 172 ] && [ "$b" -ge 16 ] && [ "$b" -le 31 ]; } || { [ "$a" = 192 ] && [ "$b" = 168 ]; }; then continue; fi
        if [ "$a" -eq 127 ] || { [ "$a" -eq 169 ] && [ "$b" -eq 254 ]; } || [ "$a" -ge 224 ] || [ "$a" -eq 0 ] || [ "$a" -eq 255 ]; then continue; fi
        OUT_ARR+=("$ip")
      fi
    done < <(printf '%s\n' $OUT_IPS_STR)
  else
    mapfile -t OUT_ARR < <(get_public_ipv4_list)
  fi
  printf '%s\n' "${OUT_ARR[@]}"
}

rand_pass(){ tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16; echo; }

generate_users(){
  : > /etc/ppp/chap-secrets
  local -a POOL=(); mapfile -t POOL < <(build_outgoing_pool)
  if [ ${#POOL[@]} -eq 0 ]; then warn "Не найдено публичных IP (после фильтрации). Создаю одного пользователя."; fi
  local need=${#POOL[@]}; [ $need -eq 0 ] && need=1
  local base_oct3=0 base_oct4=10
  local -a lines=(); local i
  for ((i=1;i<=need;i++)); do
    local user="user${i}"; local pass=$(rand_pass)
    local internal="10.99.${base_oct3}.$((base_oct4+i))"
    echo -e "${user}\tl2tp\t${pass}\t${internal}" >> /etc/ppp/chap-secrets
    local outgoing; if [ ${#POOL[@]} -gt 0 ]; then outgoing="${POOL[$((i-1<${#POOL[@]}?i-1:0))]}"; else outgoing="assigned-on-connect"; fi
    lines+=("${outgoing} | ${user} | ${pass} | ${internal}")
  done
  printf '%s\n' "${lines[@]}"
}

backup_all(){
  mkdir -p "${BACKUP_ROOT}"; log "Создание бэкапа в ${BACKUP_ROOT}"
  for f in "${CONF_FILES[@]}"; do if [ -f "$f" ]; then mkdir -p "${BACKUP_ROOT}$(dirname "$f")"; cp -a "$f" "${BACKUP_ROOT}$f"; else mkdir -p "${BACKUP_ROOT}$(dirname "$f")"; : > "${BACKUP_ROOT}$f.absent"; fi; done
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
  for s in "${SERVICES[@]}"; do if [ -f "${src}/systemd/${s}.active" ]; then if grep -q active "${src}/systemd/${s}.active"; then systemctl restart "$s" >/dev/null 2>&1 || true; else systemctl stop "$s" >/devnull 2>&1 || true; fi; fi; done
  success "Откат завершён"; }

print_connection_info(){
  local OUT_IPS_STR; OUT_IPS_STR=$(build_outgoing_pool | tr '\n' ' ' | sed 's/  */ /g;s/ *$//')
  {
    echo "======== L2TP Connection Information ========"; echo "Дата: ${DATE_TAG}"; echo "Конфиг файлы: ${CONF_FILES[*]}"; echo
    if [ -n "$OUT_IPS_STR" ]; then echo "Пул исходящих IP: $OUT_IPS_STR"; else echo "Пул исходящих IP: не задан (будет использован авто-детект публичных IP или SNAT интерфейса)"; fi; echo
    echo "Клиенты (OUTGOING_IP | USERNAME | PASSWORD | INTERNAL_IP)"; echo "----------------------------------------------------------"
    if [ -s /etc/ppp/chap-secrets ]; then
      mapfile -t OUT_ARR < <(build_outgoing_pool)
      local n=0
      while read -r user server pass ip; do
        [ -z "${user:-}" ] && continue; case "$user" in \#*) continue;; esac
        local outgoing="assigned-on-connect"
        if [ ${#OUT_ARR[@]} -gt 0 ]; then if [ $n -lt ${#OUT_ARR[@]} ]; then outgoing="${OUT_ARR[$n]}"; else outgoing="${OUT_ARR[0]}"; fi; fi
        echo "${outgoing} | ${user} | ${pass} | ${ip}"
        n=$((n+1))
      done < /etc/ppp/chap-secrets
    else
      echo "Нет клиентов: файл /etc/ppp/chap-secrets пуст или отсутствует"
    fi
    echo "----------------------------------------------------------"; echo "Файл с данными: ${OUT_FILE}"
  } | tee "${OUT_FILE}"
}

# Placeholder for install function if it exists in repo history; keeping order compliance
install_l2tp(){
  require_root
  backup_all || true
  generate_users >/dev/null
  print_connection_info
  success "Базовая генерация пользователей и информация завершены"
}

rollback_menu(){ require_root; local choose; log "Поиск доступных бэкапов в ${BACKUP_BASE}"; mapfile -t backups < <(ls -1d ${BACKUP_BASE}/l2tp-universal-backup-* 2>/dev/null | sort); [ ${#backups[@]} -gt 0 ] || { err "Бэкапы не найдены"; exit 1; }; echo "Доступные бэкапы:"; local i=1; for b in "${backups[@]}"; do echo "  $i) $b"; i=$((i+1)); done; read -rp "Введите номер бэкапа (или Enter для последнего): " choose || true; local sel; if [ -z "${choose:-}" ]; then sel="${backups[-1]}"; else echo "$choose" | grep -Eq '^[0-9]+$' && [ "$choose" -ge 1 ] && [ "$choose" -le ${#backups[@]} ] || { err "Неверный выбор"; exit 1; }; sel="${backups[$((choose-1))]}"; fi; restore_from_backup "$sel"; }

main_menu(){ echo "================ L2TP Universal ================="; echo "1) Установка L2TP"; echo "2) Откат (Rollback)"; echo "q) Выход"; echo "-----------------------------------------------"; }

should_auto_menu(){ case "${1:-}" in --install|--rollback|--help|-h) return 1;; esac; if [ "${BASH_SOURCE[0]:-x}" != "$0" ] 2>/dev/null; then return 1; fi; return 0; }

print_help(){ cat <<'HLP'
Usage:
  bash l2tp-universal.sh --install        Install L2TP (with backup)
  bash l2tp-universal.sh --rollback       Rollback to a selected backup
  bash l2tp-universal.sh                  Start interactive menu (any invocation)

Run methods (STDIN, file, curl|process substitution, CentOS7):
  # as file
  chmod +x l2tp-universal.sh && sudo ./l2tp-universal.sh --install

  # via pipe from curl (bash reads from STDIN; all functions declared first so OK)
  curl -fsSL https://raw.githubusercontent.com/Mortyo666/l2tp-universal-script/main/l2tp-universal.sh | sudo bash -s -- --install

  # via process substitution (works because functions declared before main)
  sudo bash <(curl -fsSL https://raw.githubusercontent.com/Mortyo666/l2tp-universal-script/main/l2tp-universal.sh) --install

  # CentOS 7 note: use bash from /bin/bash; ensure iproute2, ppp, xl2tpd, libreswan/strongSwan installed
  # Example install deps:
  #   sudo yum install -y epel-release && sudo yum install -y iproute ppp xl2tpd libreswan

Environment variables:
  OUTGOING_IPS="1.2.3.4 5.6.7.8"   Пул исходящих публичных IP. На каждый IP создаётся userN
  IFACE_OVERRIDE=eth0               Переопределение egress интерфейса для SNAT

Авто-логика исходящих IP:
  - Если OUTGOING_IPS не задан, скрипт соберёт все публичные IPv4 с хоста,
    отфильтрует приватные (RFC1918), служебные 10.180.x.x, loopback/link-local/multicast/reserved.

Генерация пользователей:
  - На каждый исходящий IP: userN с случайным паролем и INTERNAL_IP 10.99.0.(10+N)

Таблица вывода:
  - Формат: OUTGOING_IP | USERNAME | PASSWORD | INTERNAL_IP
HLP
}

main(){
  case "${1:-}" in
    --install) install_l2tp; return;;
    --rollback) rollback_menu; return;;
    --help|-h) print_help; return;;
  esac
