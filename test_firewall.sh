#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8088/api}"
TOKEN="${API_TOKEN:-secret123}"
HDR_AUTH=(-H "Authorization: Bearer ${TOKEN}")
HDR_JSON=(-H "Content-Type: application/json")

# === 根据你的实现改这里（仅路径片段，不含 /api 前缀）===
FW_PATH_ADD="${FW_PATH_ADD:-/fw/trust}"
FW_PATH_LIST="${FW_PATH_LIST:-/fw/trust}"
FW_PATH_DEL="${FW_PATH_DEL:-/fw/trust}"   # 实际删除为 ${FW_PATH_DEL}/{id}

IP="${IP:-1.2.3.4}"
PORTS="${PORTS:-8088,10001}"   # 逗号分隔
PROTO="${PROTO:-tcp}"          # tcp/udp/all

say(){ printf "\n\033[1;36m==> %s\033[0m\n" "$*"; }
jq_if(){ command -v jq >/dev/null 2>&1 && jq . || cat; }

# 1) 新增
say "新增可信 IP 规则: ip=${IP} ports=[${PORTS}] proto=${PROTO}"
ADD_PAYLOAD="$(jq -n --arg ip "$IP" --arg ports "$PORTS" --arg proto "$PROTO" \
  '{ip:$ip, ports: ($ports|split(",")|map(tonumber)), proto:$proto}')"
ADD_RESP="$(curl -fsS -X POST "${BASE_URL}${FW_PATH_ADD}" "${HDR_AUTH[@]}" "${HDR_JSON[@]}" -d "$ADD_PAYLOAD")"
echo "$ADD_RESP" | jq_if

# 取出 id（根据你的返回结构修改 jq 路径）
ID="$(echo "$ADD_RESP" | jq -r '.id // .data.id // empty')"
if [[ -z "${ID}" || "${ID}" == "null" ]]; then
  echo "⚠️ 未从返回中解析到 id，请检查接口返回字段（期望 .id 或 .data.id）。"
fi

# 2) 列表
say "列表"
curl -fsS "${BASE_URL}${FW_PATH_LIST}" "${HDR_AUTH[@]}" | jq_if

# 3) 再加一条（可选）
say "再加一条：ip=5.6.7.8 ports=[${PORTS}] proto=${PROTO}"
ADD2_PAYLOAD="$(jq -n --arg ip "5.6.7.8" --arg ports "$PORTS" --arg proto "$PROTO" \
  '{ip:$ip, ports: ($ports|split(",")|map(tonumber)), proto:$proto}')"
ADD2_RESP="$(curl -fsS -X POST "${BASE_URL}${FW_PATH_ADD}" "${HDR_AUTH[@]}" "${HDR_JSON[@]}" -d "$ADD2_PAYLOAD")"
echo "$ADD2_RESP" | jq_if

# 4) 删除第一条（如果拿到了 ID）
if [[ -n "${ID:-}" ]]; then
  say "删除规则 id=${ID}"
  curl -fsS -X DELETE "${BASE_URL}${FW_PATH_DEL}/${ID}" "${HDR_AUTH[@]}" | jq_if
else
  echo "跳过删除步骤（没有 id）。"
fi

# 5) 最终列表
say "最终列表"
curl -fsS "${BASE_URL}${FW_PATH_LIST}" "${HDR_AUTH[@]}" | jq_if

echo
echo "✅ 完成。若你的路径不同，可改：FW_PATH_ADD / FW_PATH_LIST / FW_PATH_DEL"