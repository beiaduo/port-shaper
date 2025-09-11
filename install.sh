#!/usr/bin/env bash
set -euo pipefail

REPO="beiaduo/port-shaper"
BIN_NAME="port-shaper"
BIN_DIR="/usr/local/lib/port-shaper"
BIN_PATH="${BIN_DIR}/${BIN_NAME}"
CLI_PATH="/usr/local/bin/port-shaper"   # 只做查询菜单
CONF_DIR="/etc/port-shaper"
ENV_FILE="${CONF_DIR}/env"
SERVICE_FILE="/etc/systemd/system/port-shaper.service"

DOWN_MODE_DEFAULT="police"
DEV_DEFAULT="ens3"   # 默认网卡改为 ens3

uninstall_all() {
  echo "Uninstalling Port-Shaper ..."
  systemctl stop port-shaper 2>/dev/null || true
  systemctl disable port-shaper 2>/dev/null || true
  rm -f "${SERVICE_FILE}" 2>/dev/null || true
  rm -rf "${CONF_DIR}" 2>/dev/null || true
  rm -rf "${BIN_DIR}" 2>/dev/null || true
  rm -f "${CLI_PATH}" 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
  echo "✅ Uninstalled."
  exit 0
}

if [[ "${1:-}" == "--uninstall" ]]; then
  uninstall_all
fi

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) echo "Unsupported arch: $(uname -m)" >&2; exit 1 ;;
  esac
}

random_port() { command -v shuf >/dev/null 2>&1 && shuf -i 20000-60000 -n 1 || awk -v min=20000 -v max=60000 'BEGIN{srand(); print int(min+rand()*(max-min+1))}'; }
random_token() { command -v openssl >/dev/null 2>&1 && openssl rand -hex 32 | sha256sum | awk '{print $1}' || date +%s%N | sha256sum | awk '{print $1}'; }
random_suffix() { command -v openssl >/dev/null 2>&1 && openssl rand -base64 12 | tr '+/' '-_' | tr -d '=' || date +%s%N | md5sum | cut -c1-16; }

public_ip() {
  for cmd in \
    "curl -fsS --max-time 3 https://api.ipify.org" \
    "curl -fsS --max-time 3 https://ifconfig.me" \
    "dig +short myip.opendns.com @resolver1.opendns.com"
  do
    IP=$(bash -lc "$cmd" 2>/dev/null || true)
    [[ -n "${IP:-}" ]] && { echo "$IP"; return; }
  done
  echo "0.0.0.0"
}

need_pkg() { dpkg -s "$1" >/dev/null 2>&1 || sudo apt-get install -y "$1"; }
install_deps() {
  sudo apt-get update
  need_pkg iproute2
  need_pkg curl
  need_pkg ca-certificates
  need_pkg dnsutils || true
  need_pkg coreutils || true    # 提供 shuf
  need_pkg iptables || true
}

download_binary() {
  local arch="$1" url bin_file tmp
  case "$arch" in
    amd64) bin_file="${BIN_NAME}-linux-amd64" ;;
    arm64) bin_file="${BIN_NAME}-linux-arm64" ;;
  esac
  url="https://github.com/${REPO}/releases/latest/download/${bin_file}"
  tmp="$(mktemp -d)"
  echo "Downloading ${url} ..."
  curl -fL --retry 3 --connect-timeout 5 -o "${tmp}/${BIN_NAME}" "$url"
  sudo install -d -m 0755 "${BIN_DIR}"
  sudo install -m 0755 "${tmp}/${BIN_NAME}" "${BIN_PATH}"
  rm -rf "$tmp"
}

# ---- 防火墙初始化/总开关（不依赖 API）----
FW_CHAIN="PS_TRUST"
FW_COMMENT="PS_GLOBAL_DROP"

fw_ensure_chain() {
  # 1) 创建自定义链（幂等）
  sudo iptables -N "$FW_CHAIN" 2>/dev/null || true
  # 2) 确保 INPUT 链跳到 PS_TRUST（置于靠前位置，避免被其它 ACCEPT 提前放过）
  if ! sudo iptables -C INPUT -j "$FW_CHAIN" 2>/dev/null; then
    sudo iptables -I INPUT 1 -j "$FW_CHAIN"
  fi
}

fw_chain_lines() { sudo iptables -S "$FW_CHAIN" 2>/dev/null || true; }

fw_chain_empty() {
  local lines
  lines="$(fw_chain_lines | grep -E "^-A " || true)"
  [[ -z "$lines" ]]
}

fw_enable_global_drop() {
  # 在链首插入一条带注释的全局 DROP（若不存在）
  if ! sudo iptables -C "$FW_CHAIN" -m comment --comment "$FW_COMMENT" -j DROP 2>/dev/null; then
    sudo iptables -I "$FW_CHAIN" 1 -m comment --comment "$FW_COMMENT" -j DROP
  fi
}

fw_disable_global_drop() {
  # 删除所有带注释的全局 DROP（幂等）
  local line del
  while read -r line; do
    echo "$line" | grep -q -- "--comment $FW_COMMENT" || continue
    echo "$line" | grep -q -- " -j DROP" || continue
    # 形如：-A PS_TRUST -m comment --comment PS_GLOBAL_DROP -j DROP
    del="$(echo "$line" | sed -e "s/^-A /-D /")"
    sudo iptables $del 2>/dev/null || true
  done < <(fw_chain_lines)
}

# 迁移旧 env（BASE_PATH -> SUFFIX），并生成缺失项
write_env() {
  local port token suffix
  port="$(random_port)"
  token="$(random_token)"
  suffix="$(random_suffix)"
  sudo install -d -m 0755 "${CONF_DIR}"

  if [[ -f "${ENV_FILE}" ]]; then
    sudo cp "${ENV_FILE}" "${ENV_FILE}.bak.$(date +%s)" || true
    if grep -qE '^BASE_PATH=' "${ENV_FILE}"; then
      old=$(grep -E '^BASE_PATH=' "${ENV_FILE}" | head -1 | cut -d= -f2- | sed 's#^/##')
      sudo sed -i 's/^BASE_PATH=.*/SUFFIX='"${old}"'/' "${ENV_FILE}"
    fi
    grep -qE '^SUFFIX='     "${ENV_FILE}" || echo "SUFFIX=${suffix}"             | sudo tee -a "${ENV_FILE}" >/dev/null
    grep -qE '^PORT='       "${ENV_FILE}" || echo "PORT=${port}"                 | sudo tee -a "${ENV_FILE}" >/dev/null
    grep -qE '^API_TOKEN='  "${ENV_FILE}" || echo "API_TOKEN=${token}"           | sudo tee -a "${ENV_FILE}" >/dev/null
    grep -qE '^DEV='        "${ENV_FILE}" || echo "DEV=${DEV_DEFAULT}"           | sudo tee -a "${ENV_FILE}" >/dev/null
    grep -qE '^DOWN_MODE='  "${ENV_FILE}" || echo "DOWN_MODE=${DOWN_MODE_DEFAULT}" | sudo tee -a "${ENV_FILE}" >/dev/null
    grep -qE '^IFB_ENABLE=' "${ENV_FILE}" || echo "IFB_ENABLE=1"                 | sudo tee -a "${ENV_FILE}" >/dev/null
  else
    sudo tee "${ENV_FILE}" >/dev/null <<EOF
# Auto-generated by install.sh
API_TOKEN=${token}
PORT=${port}
DEV=${DEV_DEFAULT}
SUFFIX=${suffix}
DOWN_MODE=${DOWN_MODE_DEFAULT}
IFB_ENABLE=1
EOF
  fi
  sudo sed -i '/^BASE_PATH=/d' "${ENV_FILE}"
  sudo chmod 600 "${ENV_FILE}"
}

write_service() {
  sudo tee "${SERVICE_FILE}" >/dev/null <<EOF
[Unit]
Description=Port Shaper API service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${ENV_FILE}
ExecStart=${BIN_PATH} serve
Restart=on-failure
RestartSec=2s
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=true
ProtectSystem=full
PrivateTmp=true
StandardInput=null

[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl daemon-reload
  sudo systemctl enable port-shaper
}

write_cli() {
  sudo tee "${CLI_PATH}" >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ENV="/etc/port-shaper/env"
[[ -f "$ENV" ]] || { echo "env file not found: $ENV"; exit 1; }

# ---- 封装一次读取 env ----
source_env() {
  # shellcheck disable=SC1090
  source "$ENV"
}

# shellcheck disable=SC1090
source "$ENV"

get_local_ip(){ ip route get 8.8.8.8 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || echo 127.0.0.1; }
get_public_ip(){ [[ -n "${1:-}" ]] && echo "$1" && return; command -v curl >/dev/null 2>&1 && curl -fsS --max-time 3 https://api.ipify.org || true; }

FW_CHAIN="PS_TRUST"
FW_COMMENT="PS_GLOBAL_DROP"

fw_ensure_chain(){
  sudo iptables -N "$FW_CHAIN" 2>/dev/null || true
  if ! sudo iptables -C INPUT -j "$FW_CHAIN" 2>/dev/null; then
    sudo iptables -I INPUT 1 -j "$FW_CHAIN"
  fi
}
fw_enable_global_drop(){
  if ! sudo iptables -C "$FW_CHAIN" -m comment --comment "$FW_COMMENT" -j DROP 2>/dev/null; then
    sudo iptables -I "$FW_CHAIN" 1 -m comment --comment "$FW_COMMENT" -j DROP
  fi
}
fw_disable_global_drop(){
  local line del
  while read -r line; do
    echo "$line" | grep -q -- "--comment $FW_COMMENT" || continue
    echo "$line" | grep -q -- " -j DROP" || continue
    del="$(echo "$line" | sed -e 's/^-A /-D /')"
    sudo iptables $del 2>/dev/null || true
  done < <(sudo iptables -S "$FW_CHAIN" 2>/dev/null || true)
}

show_info(){
  local L P U
  L="$(get_local_ip)"; P="$(get_public_ip "${1:-}")"; [[ -z "$P" ]] && P="$L"
  U="/${SUFFIX#/}"
  echo "================ Port Shaper ================"
  echo "Dev:          ${DEV}"
  echo "Port:         ${PORT}"
  echo "Suffix:       ${U}"
  echo "Down Mode:    ${DOWN_MODE}"
  echo "IFB Enable:   ${IFB_ENABLE}"
  echo "API Token:    ${API_TOKEN}"
  echo "---------------------------------------------"
  echo "Local URL:    http://${L}:${PORT}${U}"
  echo "Public URL:   http://${P}:${PORT}${U}"
  echo "============================================="
}


change_dev(){
  read -rp "请输入新的网卡名(当前: ${DEV}): " newdev
  [[ -z "${newdev}" ]] && { echo "未修改"; return; }

  # 1) 校验网卡是否存在
  if ! ip link show "$newdev" >/dev/null 2>&1; then
    echo "❌ 网卡 ${newdev} 不存在。可用网卡："
    ip -o link show | awk -F': ' '{print " - "$2}'
    return
  fi

  # 2) 写入 env
  sudo sed -i "s/^DEV=.*/DEV=${newdev}/" "$ENV"

  # 3) 重启服务并重新加载 env 到当前脚本
  echo "已修改为: ${newdev}，正在重启服务..."
  sudo systemctl restart port-shaper

  # 4) 重新读取配置，刷新当前 Shell 里的 DEV/PORT 等变量
  source_env

  # 5) 给个简短状态
  systemctl is-active --quiet port-shaper \
    && echo "✅ 服务已启动，当前 DEV=${DEV}" \
    || (echo "⚠️ 服务未处于 active，可用 2) 查看状态/3) 看日志排查"; return)
}

do_uninstall(){
  echo "确认卸载 Port-Shaper? [y/N]"
  read -r ans
  [[ "${ans,,}" != "y" ]] && { echo "已取消"; return; }
  sudo systemctl stop port-shaper || true
  sudo systemctl disable port-shaper || true
  sudo rm -f /etc/systemd/system/port-shaper.service
  sudo rm -rf /etc/port-shaper
  sudo rm -rf /usr/local/lib/port-shaper
  sudo rm -f /usr/local/bin/port-shaper
  sudo systemctl daemon-reload
  echo "✅ Port-Shaper 已卸载"
  echo "bash <(curl -fsSL https://raw.githubusercontent.com/beiaduo/port-shaper/main/install.sh)"

}

menu(){
  while true; do
    echo
    echo " 1) 查看访问信息"
    echo " 2) 查看 systemd 状态"
    echo " 3) 查看最近日志"
    echo " 4) 重启服务"
    echo " 5) 修改网卡 (当前: ${DEV})"
    echo " 6) 卸载 Port-Shaper"
    echo " 7) 开启全部 DROP（默认全拒绝）"
    echo " 8) 取消全部 DROP"
    echo " 0) 退出"
    read -rp "请选择: " c
    case "$c" in
      1) show_info ;;
      2) systemctl status port-shaper --no-pager ;;
      3) journalctl -u port-shaper -n 100 --no-pager ;;
      4) systemctl restart port-shaper && echo "已重启" ;;
      5) change_dev ;;
      6) do_uninstall; exit 0 ;;
      7) fw_ensure_chain; fw_enable_global_drop; echo "✅ 已开启全部 DROP" ;;
      8) fw_disable_global_drop; echo "✅ 已取消全部 DROP" ;;
      0) exit 0 ;;
      *) echo "无效选择" ;;
    esac
  done
}

if [[ -t 1 ]]; then menu; else show_info "$@"; fi
EOF
  sudo chmod +x "${CLI_PATH}"
}

start_service() {
  sudo systemctl restart port-shaper
  sleep 1
  sudo systemctl --no-pager --full status port-shaper || true
}

main() {
  install_deps
  ARCH="$(detect_arch)"
  PUBIP="$(public_ip)"

  download_binary "$ARCH"
  write_env
  write_service
  start_service
  write_cli

  # ---- 首次安装：默认全拒绝（全部 DROP）----
  fw_ensure_chain
  if fw_chain_empty; then
    fw_enable_global_drop
    echo "[install] PS_TRUST is empty -> inserted global DROP (default deny all)."
  fi

  # shellcheck disable=SC1091
  source "${ENV_FILE}"
  echo
  echo "=========== INSTALL SUMMARY ==========="
  echo "Binary:      ${BIN_PATH}"
  echo "CLI:         ${CLI_PATH}"
  echo "Config:      ${ENV_FILE}"
  echo "Service:     ${SERVICE_FILE}"
  echo "---------------------------------------"
  echo "Local URL:   http://127.0.0.1:${PORT}/${SUFFIX}"
  echo "Public URL:  http://${PUBIP}:${PORT}/${SUFFIX}"
  echo "API Token:   ${API_TOKEN}"
  echo "Dev:         ${DEV}"
  echo "Down Mode:   ${DOWN_MODE}"
  echo "IFB Enable:  ${IFB_ENABLE}"
  echo "---------------------------------------"
  echo "查看信息/菜单： port-shaper"
  echo "非交互输出：   port-shaper ${PUBIP}"
  echo "卸载：         bash install.sh --uninstall"
  echo "======================================="
}

main "$@"