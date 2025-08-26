readme_content = """# Port-Shaper

轻量级端口限速工具，基于 `tc`，支持上/下行限速，自动生成 API Token 和随机路径。

---

## 🚀 一条安装命令

```bash
curl -fsSL https://raw.githubusercontent.com/beiaduo/port-shaper/main/install.sh | bash
```

---

## 📌 使用方法

安装完成后运行：

```bash
port-shaper
```

进入交互菜单，可执行以下操作：

- `1` 查看访问信息（API 地址 / Token / URL）
- `2` 查看 systemd 状态
- `3` 查看最近日志
- `4` 重启服务
- `5` 修改网卡
- `6` 卸载 Port-Shaper
- `0` 退出

---

## ❌ 卸载

```bash
port-shaper --uninstall
```

---

## 🔗 API 示例

### 限速端口
限制端口 `10100` 上下行 `5Mbit`：

```bash
curl -X POST http://<服务器IP>:<端口>/<路径>/limit \\
  -H "Authorization: Bearer <API_TOKEN>" \\
  -d '{"dev":"ens3","port":10100,"up":"5mbit","down":"5mbit","oid":"test-123"}'
```

### 解除限速
```bash
curl -X POST http://<服务器IP>:<端口>/<路径>/unlimit \\
  -H "Authorization: Bearer <API_TOKEN>" \\
  -d '{"port":10100}'
```

---

## 📖 LICENSE
MIT
"""

with open("/mnt/data/README.md", "w") as f:
f.write(readme_content)

"/mnt/data/README.md"