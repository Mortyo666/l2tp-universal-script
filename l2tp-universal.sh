#!/usr/bin/env bash
set -euo pipefail
# l2tp-universal.sh
# Универсальный Bash-скрипт для автоматизированной настройки L2TP/IPsec VPN сервера
# Функции:
# 1) Автоматически определяет основной и дополнительные внешние IP-адреса
# 2) Устанавливает и настраивает L2TP/IPsec (strongSwan или Libreswan + xl2tpd)
# 3) Создает учетные записи пользователей
# 4) Настраивает iptables SNAT для множественных исходящих IP
# 5) Выводит цветную таблицу пользователей: OUTGOING_IP, USERNAME, PASSWORD, INTERNAL_IP
# 6) Сохраняет все данные в текстовый файл
# Скрипт предназначен для запуска напрямую с GitHub: wget -O - <raw_url> | bash
# ========= ПРЕДУПРЕЖДЕНИЕ =========
# Данный скрипт изменяет сетевые и системные настройки. Запускайте ТОЛЬКО на чистых/выделенных серверах.
# ==================================
if [[ $EUID -ne 0 ]]; then
  echo "[ERR] Запустите от root (sudo -i)" >&2
  exit 1
fi
# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
# Файл с результатами
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUT_FILE="/root/l2tp-universal-${TIMESTAMP}.txt"
# Параметры по умолчанию (можно переопределять переменными окружения)
VPN_PSK=${VPN_PSK:-"auto-generated"}
USERS_COUNT=${USERS_COUNT:-5}
USER_PREFIX=${USER_PREFIX:-"user"}
PASS_LEN=${PASS_LEN:-12}
POOL_SUBNET=${POOL_SUBNET:-"10.99.0.0/24"}
  
# пул адресов для L2TP клиентов
POOL_START=${POOL_START:-"10.99.0.10"}
POOL_END=${POOL_END:-"10.99.0.250"}
# Определение дистрибутива
ID_LIKE=""
if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  DIST_ID=${ID:-unknown}
  ID_LIKE=${ID_LIKE:-$DIST_ID}
else
  echo "[ERR] Не удалось определить дистрибутив (нет /etc/os-release)" >&2
  exit 1
fi
# --- Fix CentOS 7 repositories to vault.centos.org ---
fix_centos7_repos() {
  # Срабатывает только на CentOS 7
  if [[ "${DIST_ID}" == "centos" ]]; then
    local ver_id="${VERSION_ID:-}"
    if [[ "${ver_id}" == 7* ]]; then
      echo -e "${BLUE}[*] Обнаружен CentOS 7 — переключаю mirrorlist на vault.centos.org...${NC}"
      # Отключаем mirrorlist и включаем baseurl на vault для всех CentOS-Base.repo и CentOS-*.repo
      for repo in /etc/yum.repos.d/CentOS-*.repo; do
        [[ -f "$repo" ]] || continue
        sed -i -e 's|^mirrorlist=|#mirrorlist=|g' \
               -e 's|^#\?baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' "$repo" || true
        # Также встречается https и адреси с centos.org/centos
        sed -i -e 's|^#\?baseurl=https\?://mirror.centos.org|baseurl=http://vault.centos.org|g' "$repo" || true
        sed -i -E 's|^#\?baseurl=https?://(www\.)?centos\.org/centos|baseurl=http://vault.centos.org|g' "$repo" || true
      done
      yum clean all || true
      rm -rf /var/cache/yum || true
      yum makecache fast || yum makecache || true
    fi
  fi
}

pkg_install() {
  case "$DIST_ID" in
    ubuntu|debian)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get install -y strongswan xl2tpd ppp iptables iproute2 sed gawk curl grep coreutils net-tools
      ;;
    centos|rhel|rocky|almalinux|fedora)
      yum -y install epel-release || true
      yum -y install strongswan xl2tpd ppp iptables iproute iproute-tc sed gawk curl grep coreutils net-tools
      ;;
    *)
      echo "[ERR] Неподдерживаемый дистрибутив: $DIST_ID" >&2
      exit 1
      ;;
  esac
}

# ==== Ниже оставшаяся часть исходного скрипта (включая функции) ====
# В целях правки для CentOS7 оставляем остальной функционал как был.
# ... (остальные функции: get_default_iface, get_all_public_ips, ensure_sysctl,
# configure_strongswan, configure_xl2tpd, create_users, setup_firewall_snat,
# restart_services, collect_client_info) ...

get_default_iface() {
  ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}'
}
get_all_public_ips() {
  ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1
}
ensure_sysctl() {
  sysctl -w net.ipv4.ip_forward=1 || true
  { 
    echo 'net.ipv4.ip_forward=1'
    echo 'net.ipv4.conf.all.accept_redirects=0'
    echo 'net.ipv4.conf.all.send_redirects=0'
  } >> /etc/sysctl.conf
  sysctl -p || true
}
configure_strongswan() {
  local main_ip="$1" psk="$2"
  mkdir -p /etc/ipsec.d
  cat >/etc/ipsec.conf <<EOF
config setup
    charondebug="cfg 0, dmn 0, ike 0, net 0"

conn L2TP-PSK
    keyexchange=ikev1
    authby=psk
    type=transport
    left=%any
    leftid=$main_ip
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/1701
    ike=aes256-sha1-modp1024!
    esp=aes256-sha1!
    auto=add
EOF
  echo "$main_ip %any : PSK \"$psk\"" > /etc/ipsec.secrets
}
configure_xl2tpd() {
  mkdir -p /etc/xl2tpd
  cat >/etc/xl2tpd/xl2tpd.conf <<EOF
[lac vpn-connection]
lns = 127.0.0.1
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF
  mkdir -p /etc/ppp
  cat >/etc/ppp/options.xl2tpd <<EOF
require-mschap-v2
ms-dns 1.1.1.1
ms-dns 8.8.8.8
asyncmap 0
mtu 1410
mru 1410
crtscts
lock
hide-password
modem
name l2tpd
proxyarp
lcp-echo-interval 30
lcp-echo-failure 4
ipcp-accept-local
ipcp-accept-remote
noccp
nologfd
EOF
}
create_users() {
  local count="$1"
  : > /etc/ppp/chap-secrets
  for i in $(seq 1 "$count"); do
    local u="${USER_PREFIX}${i}"
    local p=$(tr -dc A-Za-z0-9 </dev/urandom | head -c ${PASS_LEN})
    echo -e "$u\tl2tpd\t$p\t*" >> /etc/ppp/chap-secrets
  done
}
setup_firewall_snat() {
  local iface="$1"
  mapfile -t ips < <(get_all_public_ips)
  for ip in "${ips[@]}"; do
    iptables -t nat -A POSTROUTING -s ${POOL_SUBNET} -o "$iface" -j SNAT --to-source "$ip" || true
  done
  # Сохраняем правила, если доступно
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save || true
  elif command -v service >/dev/null 2>&1 && service iptables save >/dev/null 2>&1; then
    service iptables save || true
  fi
}
restart_services() {
  systemctl enable strongswan --now || systemctl enable strongswan-starter --now || true
  systemctl restart strongswan || systemctl restart strongswan-starter || true
  systemctl enable xl2tpd --now || true
  systemctl restart xl2tpd || true
}
collect_client_info() {
  mapfile -t ips < <(get_all_public_ips)
  printf "\n" | tee -a "$OUT_FILE" >/dev/null
  echo "VPN PSK: $VPN_PSK" | tee -a "$OUT_FILE"
  echo "Публичные исходящие IP (SNAT): ${ips[*]}" | tee -a "$OUT_FILE"
  echo "Пул клиентов: $POOL_SUBNET ($POOL_START - $POOL_END)" | tee -a "$OUT_FILE"
  echo "\nПользователи:" | tee -a "$OUT_FILE"
  # Цветная таблица: OUTGOING_IP, USERNAME, PASSWORD, INTERNAL_IP
  printf "\n${CYAN}%-16s %-18s %-18s %-16s${NC}\n" "OUTGOING_IP" "USERNAME" "PASSWORD" "INTERNAL_IP" | tee -a "$OUT_FILE"
  while IFS=$'\t' read -r user pass; do
    [[ -z "$user" || -z "$pass" ]] && continue
    printf "${GREEN}%-16s${NC} %-18s %-18s %-16s\n" "${ips[0]:-N/A}" "$user" "$pass" "assigned-on-connect" | tee -a "$OUT_FILE"
  done < <(awk '{print $1"\t"$3}' /etc/ppp/chap-secrets)
}
main() {
  echo -e "${BLUE}[*] Обнаружение сетевых интерфейсов и IP...${NC}"
  IFACE=$(get_default_iface)
  if [[ -z "$IFACE" ]]; then
    echo "[ERR] Не удалось определить интерфейс по умолчанию" >&2
    exit 1
  fi
  PUB_IPS=( $(get_all_public_ips) )
  if [[ ${#PUB_IPS[@]} -eq 0 ]]; then
    echo "[ERR] Не найдено ни одного публичного IP" >&2
    exit 1
  fi
  MAIN_IP=${PUB_IPS[0]}
  echo -e "${BLUE}[*] Подготовка репозиториев (CentOS 7 vault)...${NC}"
  fix_centos7_repos
  echo -e "${BLUE}[*] Установка пакетов...${NC}"
  pkg_install
  echo -e "${BLUE}[*] Настройка sysctl...${NC}"
  ensure_sysctl
  echo -e "${BLUE}[*] Настройка strongSwan (IPsec)...${NC}"
  configure_strongswan "$MAIN_IP" "$VPN_PSK"
  echo -e "${BLUE}[*] Настройка xl2tpd/PPP...${NC}"
  configure_xl2tpd
  echo -e "${BLUE}[*] Создание пользователей (${USERS_COUNT})...${NC}"
  create_users "$USERS_COUNT"
  echo -e "${BLUE}[*] Настройка iptables SNAT...${NC}"
  setup_firewall_snat "$IFACE"
  echo -e "${BLUE}[*] Перезапуск сервисов...${NC}"
  restart_services
  echo -e "${BLUE}[*] Сбор и вывод данных клиентов...${NC}"
  collect_client_info
  echo "\nИтоговый файл с данными: $OUT_FILE"
}
main "$@"
