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
POOL_SUBNET=${POOL_SUBNET:-"10.99.0.0/24"}  # пул адресов для L2TP клиентов
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
# Определение интерфейса выхода в интернет
get_default_iface() {
  ip route show default 0.0.0.0/0 | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}'
}
# Сбор внешних IP
get_public_ips() {
  local iface="$1"
  ip -o -4 addr show dev "$iface" | awk '{print $4}' | cut -d/ -f1
}
# Также попытаемся собрать все внешние IP с всех интерфейсов, исключая приватные
get_all_public_ips() {
  ip -o -4 addr show | awk '{print $4}' | cut -d/ -f1 | grep -Ev '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' | sort -u
}
random_password() {
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$PASS_LEN"
}
ensure_sysctl() {
  # Включаем маршрутизацию и разрешаем форвардинг
  sed -i 's/^#\?net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
  sed -i 's/^#\?net.ipv4.conf.all.accept_redirects.*/net.ipv4.conf.all.accept_redirects=0/' /etc/sysctl.conf
  sed -i 's/^#\?net.ipv4.conf.all.send_redirects.*/net.ipv4.conf.all.send_redirects=0/' /etc/sysctl.conf
  sed -i 's/^#\?net.ipv4.conf.default.accept_redirects.*/net.ipv4.conf.default.accept_redirects=0/' /etc/sysctl.conf
  sed -i 's/^#\?net.ipv4.conf.default.send_redirects.*/net.ipv4.conf.default.send_redirects=0/' /etc/sysctl.conf
  sysctl -p || sysctl -p /etc/sysctl.conf || true
}
configure_strongswan() {
  local public_ip="$1"
  local psk="$2"
  mkdir -p /etc/ipsec.d
  cat >/etc/ipsec.conf <<EOF
config setup
  charondebug="ike 1, knl 1, cfg 0"
conn L2TP-PSK
  keyexchange=ikev1
  type=transport
  left=%any
  leftprotoport=17/1701
  right=%any
  rightprotoport=17/1701
  authby=secret
  ike=aes256-sha1-modp1024!
  esp=aes256-sha1!
  auto=add
EOF
  # ipsec.secrets
  if [[ "$psk" == "auto-generated" ]]; then
    psk=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)
  fi
  VPN_PSK="$psk"
  echo "%any %any : PSK \"$psk\"" >/etc/ipsec.secrets
}
configure_xl2tpd() {
  mkdir -p /etc/xl2tpd
  cat >/etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701
[lns default]
ip range = ${POOL_START}-${POOL_END}
local ip = ${POOL_START}
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
ppp debug = no
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF
  mkdir -p /etc/ppp
  cat >/etc/ppp/options.xl2tpd <<'EOF'
iauth
name l2tpd
refuse-pap
auth
ms-dns 1.1.1.1
ms-dns 8.8.8.8
mtu 1410
mru 1410
nodefaultroute
# push default route through server
lock
nobsdcomp
novj
novjccomp
nologfd
proxyarp
lcp-echo-failure 4
lcp-echo-interval 30
ipcp-accept-local
ipcp-accept-remote
EOF
}
create_users() {
  local count="$1"
  : > /etc/ppp/chap-secrets
  : > /etc/ppp/l2tp-secrets.txt
  for i in $(seq 1 "$count"); do
    local user="${USER_PREFIX}${i}"
    local pass="$(random_password)"
    echo -e "${user}\tl2tpd\t${pass}\t*" >> /etc/ppp/chap-secrets
    # файл с итоговыми данными теперь в порядке: OUTGOING_IP USERNAME PASSWORD
    echo -e "${MAIN_IP}\t${user}\t${pass}" >> /etc/ppp/l2tp-secrets.txt
  done
  chmod 600 /etc/ppp/chap-secrets /etc/ppp/l2tp-secrets.txt
}
setup_firewall_snat() {
  local iface="$1"
  # Разрешаем L2TP/IPsec
  iptables -A INPUT -p udp --dport 500 -j ACCEPT || true
  iptables -A INPUT -p udp --dport 4500 -j ACCEPT || true
  iptables -A INPUT -p udp --dport 1701 -m policy --dir in --pol ipsec -j ACCEPT || true
  iptables -A INPUT -p udp --dport 1701 -j DROP || true
  # Разрешаем пересылку
  iptables -A FORWARD -s ${POOL_SUBNET} -j ACCEPT || true
  iptables -A FORWARD -d ${POOL_SUBNET} -j ACCEPT || true
  # Настройка SNAT для всех публичных IP
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
