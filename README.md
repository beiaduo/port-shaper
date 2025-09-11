readme_content = """# Port-Shaper

面向单机（容器/裸机）的**端口带宽整形 + 访问白名单**服务。
- 带宽：基于 `tc` + HTB/u32（上行）与 ingress police（下行）对**指定端口**限速
- 防火墙：基于 `iptables` 的**按端口白名单**（TCP+UDP 同步），默认**全拒绝**，仅放行配置的 IP

---

## 功能一览

### 带宽整形（Limits）
- `POST /{SUFFIX}/limit`：设置某端口上/下行速率（单位自动识别并 +2Mbps 冗余后用 `<N>mbit` 下发）
- `POST /{SUFFIX}/unlimit`：清除该端口限速
- `POST /{SUFFIX}/unlimit_all`：清除全部限速（含 egress/ingress qdisc）
- `GET  /{SUFFIX}/limits`：查看当前进程内记录的端口限速项
- `GET  /{SUFFIX}/limits/{port}`：查询某端口的限速项
> 备注：当 `down` 为空但 `up` 有值时，**默认 down=up**，避免旧 police 残留。

### 访问白名单（Firewalls）
- `POST /{SUFFIX}/firewalls/{port}`：**设定（set）语义**
    - `{"ips":["1.1.1.1","2.2.2.2"]}` → 替换该 `port` 的白名单为这 **去重** 后的 IP 集合（**TCP+UDP** 同步），并在链尾追加 `DROP`（默认拒绝）
    - `{"ips":[]}`（空数组）→ **删除** 该 `port` 的所有放行规则（TCP+UDP 全删）
- `GET  /{SUFFIX}/firewalls`：返回**所有端口**及每个端口的白名单 IP 列表
- `GET  /{SUFFIX}/firewalls/{port}`：返回该端口白名单 IP 列表
> 全局链为 `PS_TRUST`，并通过 `-I INPUT 1 -j PS_TRUST` 挂至 INPUT 链首；**修改执行后保持“白名单优先 + 尾部 DROP 全拒绝”**。

### 其他
- `GET /{SUFFIX}/health`：健康检查
- 认证：`Authorization: Bearer <API_TOKEN>` 或 `X-API-Token: <API_TOKEN>` 或 `?token=<API_TOKEN>`

---

## 快速开始（Docker）

### 1) 构建镜像（多阶段构建）
```bash
docker build -t port-shaper:latest .
```

> 需要的内核/工具：`tc`（来自 `iproute2`）和 `iptables`。  
> 本仓库 Dockerfile 已在运行层安装 `iproute2 iputils-ping curl ca-certificates`。

### 2) 运行容器
```bash
docker run --rm -it --name port-shaper \\
  --cap-add NET_ADMIN --cap-add NET_RAW \\
  -e API_TOKEN=secret123 \\
  -e DEV=eth0 \\
  -e PORT=8088 \\
  -e SUFFIX=api \\
  -p 8088:8088 \\
  port-shaper:latest serve
```

环境变量
- `API_TOKEN`：访问令牌（必填，示例 `secret123`）
- `DEV`：要整形的网卡（容器中一般是 `eth0`；裸机可为 `ens3`/`eno1` 等）
- `PORT`：HTTP 服务监听端口
- `SUFFIX`：API 路由前缀（示例 `api` → 实际路由 `/api/...`）

> **必须授予 NET_ADMIN** 能力，否则 `tc/iptables` 无法生效。

---

## 一键安装（systemd，裸机）

> 需要 Debian/Ubuntu 系（apt 可用）且具 `systemd`

```bash
curl -fsSL https://raw.githubusercontent.com/beiaduo/port-shaper/main/install.sh | bash
# 安装完成后：
port-shaper         # 进入交互菜单（查看信息/改网卡/看日志/重启/卸载）
```

安装脚本会：
- 下载二进制到 `/usr/local/lib/port-shaper/port-shaper`
- 写入配置 `/etc/port-shaper/env`（含 `API_TOKEN/DEV/PORT/SUFFIX/...`）
- 安装 `systemd` 服务 `/etc/systemd/system/port-shaper.service` 并启动
- 创建 CLI 菜单 `/usr/local/bin/port-shaper`（交互切网卡、重启、卸载等）

---

## 路由与示例

> 假设：`PORT=8088`、`SUFFIX=api`、`API_TOKEN=secret123`

### 健康检查
```bash
curl -H "Authorization: Bearer secret123" \\
  http://127.0.0.1:8088/api/health
# {"success":true,"message":"ok"}
```

### 带宽整形

**设置端口 10001：上/下行各 10 Mbps（内部会自动+2）**
```bash
curl -X POST http://127.0.0.1:8088/api/limit \\
  -H "Authorization: Bearer secret123" \\
  -H "Content-Type: application/json" \\
  -d '{"oid":"test1","port":10001,"up":"10","down":"10"}'
```

**仅改上行（下行默认跟随上行）**
```bash
curl -X POST http://127.0.0.1:8088/api/limit \\
  -H "Authorization: Bearer secret123" \\
  -H "Content-Type: application/json" \\
  -d '{"oid":"test2","port":10002,"up":"50"}'
```

**删除端口 10001 的限速**
```bash
curl -X POST http://127.0.0.1:8088/api/unlimit \\
  -H "Authorization: Bearer secret123" \\
  -H "Content-Type: application/json" \\
  -d '{"port":10001}'
```

**清空所有限速**
```bash
curl -X POST http://127.0.0.1:8088/api/unlimit_all \\
  -H "Authorization: Bearer secret123"
```

**查看当前限速项**
```bash
curl -H "Authorization: Bearer secret123" \\
  http://127.0.0.1:8088/api/limits
```

**查看端口 10002 的限速项**
```bash
curl -H "Authorization: Bearer secret123" \\
  http://127.0.0.1:8088/api/limits/10002
```

### 访问白名单

**为 8088 端口设置白名单（只允许 192.168.65.1 与 172.17.0.1 访问）**
```bash
curl -X POST http://127.0.0.1:8088/api/firewalls/8088 \\
  -H "Authorization: Bearer secret123" \\
  -H "Content-Type: application/json" \\
  -d '{"ips":["192.168.65.1","172.17.0.1"]}'
# 返回：{"success":true,"message":"set ok (default deny)"}
```

**清空 8088 白名单**
```bash
curl -X POST http://127.0.0.1:8088/api/firewalls/8088 \\
  -H "Authorization: Bearer secret123" \\
  -H "Content-Type: application/json" \\
  -d '{"ips":[]}'
```

**获取全部端口的白名单**
```bash
curl -H "Authorization: Bearer secret123" \\
  http://127.0.0.1:8088/api/firewalls
```

**获取端口 10001 的白名单**
```bash
curl -H "Authorization: Bearer secret123" \\
  http://127.0.0.1:8088/api/firewalls/10001
```

---

## 常见问题（Troubleshooting）

### 1）`404 page not found`
- 确认 `SUFFIX`。若 `SUFFIX=api`，路由应为 `/api/health`、`/api/limit` 等。
- 确认服务已启动：容器日志里应看到 `API listening on :8088 /api`。

### 2）`unauthorized`
- 确认请求中携带了 `Authorization: Bearer <API_TOKEN>` 或 `X-API-Token: <API_TOKEN>`。

### 3）启用白名单后 API 端口无法访问
- 你需要把**自己访问 API 的来源 IP**加入该端口的白名单。
- Docker Desktop/Mac 常见来源：`192.168.65.1`；Linux 桥接：`172.17.0.1`

### 4）容器里没有 `iptables` 或 `tc`
- 使用本仓库 Dockerfile 构建的镜像，已安装 `iproute2`（包含 `tc`）和 `iptables`。

---

## 许可证

