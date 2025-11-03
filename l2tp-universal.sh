======== L2TP Connection Information ========"; echo "Дата: ${DATE_TAG}"; echo "Конфиг файлы: ${CONF_FILES[*]}"; echo
    if [ -n "$OUT_IPS_STR" ]; then echo "Исходящие публичные IP: $OUT_IPS_STR"; else echo "Исходящие публичные IP: (не обнаружены, будет назначено при подключении)"; fi
    echo
    echo "Таблица пользователей (OUTGOING_IP | USERNAME | PASSWORD | INTERNAL_IP):"
    if [ -f "$OUT_FILE" ]; then cat "$OUT_FILE"; else echo "(таблица будет сгенерирована при установке)"; fi
  } | tee "/root/l2tp-info-${DATE_TAG}.txt"
}

install_l2tp(){
  require_root
  log "Начало установки L2TP"
  backup_all
  install_packages
  configure_sysctl
  write_basic_configs
  configure_iptables
  configure_services
  # Генерация пользователей и вывод таблицы в файл
  mapfile -t TABLE_LINES < <(generate_users)
  printf '%s\n' "${TABLE_LINES[@]}" | tee "$OUT_FILE"
  start_services
  success "Установка завершена"
  print_connection_info
}

interactive_menu(){
  echo "L2TP Universal Script"
  echo "1) Install"
  echo "2) Rollback"
  echo "3) Help"
  echo "4) Exit"
  read -rp "Select option [1-4]: " sel
  case "$sel" in
    1) install_l2tp ;;
    2) read -rp "Введите путь к бэкапу (или ${LAST_LINK}): " p; [ -z "$p" ] && p="$LAST_LINK"; restore_from_backup "$p" ;;
    3) print_help ;;
    *) exit 0 ;;
  esac
}

main(){
  local arg="${1:-}"
  case "$arg" in
    --install) install_l2tp ;;
    --rollback) shift || true; local src="${1:-$LAST_LINK}"; restore_from_backup "$src" ;;
    --help|-h) print_help ;;
    *) interactive_menu ;;
  esac
}

# Entry point must be last
main "${1:-}"
