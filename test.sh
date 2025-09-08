#!/usr/bin/env bash
set -euo pipefail

# ========== 可配置（也可用环境变量覆盖） ==========
BASE_URL="${BASE_URL:-http://127.0.0.1:8088/api}"
TOKEN="${API_TOKEN:-secret123}"
DEV="${DEV:-eth0}"
TEST_PORT="${TEST_PORT:-10001}"
UP_MB="${UP_MB:-10}"      # 将自动+2，下发为 12mbit
DOWN_MB="${DOWN_MB:-10}"  # 将自动+2，下发为 12mbit

# ========== 杂项 ==========
HDR_AUTH=(-H "Authorization: Bearer ${TOKEN}")
HDR_JSON=(-H "Content-Type: application/json")

say() { printf "\n\033[1;36m==> %s\033[0m\n" "$*"; }
ok()  { printf "\033[1;32m✔ %s\033[0m\n" "$*"; }
err() { printf "\033[1;31m✘ %s\033[0m\n" "$*" >&2; }

jq_if() {
  # 如果系统装了 jq，就用 jq 美化；否则原样输出
  if command -v jq >/dev/null 2>&1; then jq .; else cat; fi
}

# 失败时展示最近一步的响应
trap 'err "脚本执行失败（上一条步骤可能出错）。请查看上面输出。"' ERR

# ========== 1) 健康检查 ==========
say "健康检查 ${BASE_URL}/health"
curl -fsS "${HDR_AUTH[@]}" "${BASE_URL}/health" | jq_if
ok "健康检查通过"

# ========== 2) 设置限速 ==========
say "设置限速: dev=${DEV} port=${TEST_PORT} up=${UP_MB} down=${DOWN_MB}"
curl -fsS -X POST "${BASE_URL}/limit" \
  "${HDR_AUTH[@]}" "${HDR_JSON[@]}" \
  -d "$(cat <<JSON
{
  "oid":"test-run-$(date +%s)",
  "dev":"${DEV}",
  "port":${TEST_PORT},
  "up":"${UP_MB}",
  "down":"${DOWN_MB}"
}
JSON
)" | tee /tmp/ps_limit_resp.json | jq_if
ok "限速下发完成（预期 up/down = $((${UP_MB}+2))mbit / $((${DOWN_MB}+2))mbit）"

# ========== 3) 查询单端口 ==========
say "查询单端口: ${BASE_URL}/limits/${TEST_PORT}"
curl -fsS "${HDR_AUTH[@]}" "${BASE_URL}/limits/${TEST_PORT}" | jq_if
ok "单端口查询 OK"

# ========== 4) 查询全部规则 ==========
say "查询全部规则: ${BASE_URL}/limits"
curl -fsS "${HDR_AUTH[@]}" "${BASE_URL}/limits" | jq_if
ok "全部规则查询 OK"

# ========== 5) 解除单端口限速 ==========
say "解除限速: port=${TEST_PORT}"
curl -fsS -X POST "${BASE_URL}/unlimit" \
  "${HDR_AUTH[@]}" "${HDR_JSON[@]}" \
  -d "$(cat <<JSON
{"dev":"${DEV}","port":${TEST_PORT}}
JSON
)" | jq_if
ok "解除单端口限速 OK"

# ========== 6) 清空全部（可选） ==========
say "清空全部规则（可选）"
curl -fsS -X POST "${BASE_URL}/unlimit_all" \
  "${HDR_AUTH[@]}" "${HDR_JSON[@]}" \
  -d "{\"dev\":\"${DEV}\"}" | jq_if
ok "清空完成"

say "全部测试完成 ✅"
echo
echo "你可调整变量后再次测试，例如："
echo "  API_TOKEN=secret123 DEV=${DEV} PORT=8088 SUFFIX=api TEST_PORT=20001 UP_MB=20 DOWN_MB=15 bash ./test.sh"