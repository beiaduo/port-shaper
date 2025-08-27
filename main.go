package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/gorilla/mux"
)

/*
  Port-Shaper (Debian / IPv4)
  - Up：root 1: 下 HTB class(1:<hex(port)>)，配 TCP/UDP 的 u32 过滤器（sport+dport）
  - Down：ingress(ffff:) 下 TCP/UDP dport 的 police
  - 速率：支持 "60" / "60m" / "60mbit" / "60000kbit"；统一解析为 Mbps 并自动 +2Mbps 下发 "<N>mbit"
  - 健壮性：
      * 确保 HTB 根(1:) 存在；确保 ingress 存在（兼容 exclusivity/exists）
      * 变更前先删旧 prio 的过滤器，再重建（避免多条叠加导致旧值生效）
      * Down 为空时默认跟随 Up，避免只改上行但下行仍卡旧 police
*/

// -------- 数据结构 --------
type LimitRequest struct {
	OID  string `json:"oid"`
	Dev  string `json:"dev"`
	Port int    `json:"port"`
	Up   string `json:"up,omitempty"`   // 传 "60" 即可
	Down string `json:"down,omitempty"` // 可省略：默认跟随 Up
}

type APIResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`

	OID      string `json:"oid"`
	Dev      string `json:"dev"`
	Port     int    `json:"port"`
	Up       string `json:"up,omitempty"`   // 实际下发（含 +2 与单位）
	Down     string `json:"down,omitempty"` // 实际下发（含 +2 与单位）
	ClassID  string `json:"classid,omitempty"`
	DownMode string `json:"down_mode,omitempty"`
}

type ClearAllRequest struct {
	OID string `json:"oid"`
	Dev string `json:"dev"`
}

// -------- 运行时状态 --------
var (
	apiToken = "changeme"
	devName  = "eth0"
	httpPort = "8088"
	suffix   = "" // 路由前缀

	stateMu sync.RWMutex
	state   = map[int]LimitRequest{} // 仅展示用途
)

// -------- 通用工具 --------
func writeJSON(w http.ResponseWriter, code int, resp APIResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(resp)
}

func runTc(args ...string) error {
	cmd := exec.Command("tc", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return errors.New(msg)
	}
	return nil
}

func classIDFromPort(port int) string { return fmt.Sprintf("1:%x", port) }

func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no such file") ||
		strings.Contains(s, "not found") ||
		strings.Contains(s, "cannot find") ||
		strings.Contains(s, "invalid handle")
}

// 启动时初始化：重置 root 并建默认大口子（会清空既有 root 规则）
func ensureBase(dev string) {
	_ = runTc("qdisc", "del", "dev", dev, "root")
	_ = runTc("qdisc", "add", "dev", dev, "root", "handle", "1:", "htb", "default", "999")
	_ = runTc("class", "add", "dev", dev, "parent", "1:", "classid", "1:999",
		"htb", "rate", "10gbit", "ceil", "10gbit")
}

// 确保 HTB 根存在（存在则不动；不存在则创建 1: 与 1:999）
func ensureHTBRoot(dev string) error {
	out, _ := exec.Command("tc", "qdisc", "show", "dev", dev).CombinedOutput()
	low := strings.ToLower(string(out))
	if strings.Contains(low, "qdisc htb 1:") {
		return nil
	}
	_ = runTc("qdisc", "del", "dev", dev, "root")
	if err := runTc("qdisc", "add", "dev", dev, "root", "handle", "1:", "htb", "default", "999"); err != nil {
		return err
	}
	return runTc("class", "add", "dev", dev, "parent", "1:", "classid", "1:999",
		"htb", "rate", "10gbit", "ceil", "10gbit")
}

// 确保 ingress 存在；兼容 exclusivity/exists；必要时先删再加
func ensureIngress(dev string) error {
	if err := runTc("qdisc", "add", "dev", dev, "ingress"); err != nil {
		es := strings.ToLower(err.Error())
		if strings.Contains(es, "file exists") || strings.Contains(es, "exists") ||
			strings.Contains(es, "exclusivity flag on") {
			out, _ := exec.Command("tc", "qdisc", "show", "dev", dev).CombinedOutput()
			low := strings.ToLower(string(out))
			if strings.Contains(low, "qdisc ingress ffff:") || strings.Contains(low, "qdisc clsact ffff:") {
				return nil // 已有 ffff: 可用
			}
			_ = runTc("qdisc", "del", "dev", dev, "ingress")
			if err2 := runTc("qdisc", "add", "dev", dev, "ingress"); err2 == nil {
				return nil
			}
			return fmt.Errorf("re-add ingress after del failed: %v", err)
		}
		return fmt.Errorf("add ingress failed: %v", err)
	}
	return nil
}

// -------- 速率解析（自动 +2Mbps，输出 "<N>mbit"） --------
func normalizeRateMbpsPlus2(in string) (string, error) {
	s := strings.TrimSpace(strings.ToLower(in))
	if s == "" {
		return "", errors.New("empty rate")
	}
	if strings.HasSuffix(s, "kbit") {
		num := strings.TrimSuffix(s, "kbit")
		kb, err := strconv.ParseFloat(strings.TrimSpace(num), 64)
		if err != nil {
			return "", fmt.Errorf("invalid kbit: %v", err)
		}
		mb := kb / 1000.0
		mb += 2
		return fmt.Sprintf("%.0fmbit", mb), nil
	}
	if strings.HasSuffix(s, "mbit") || strings.HasSuffix(s, "m") {
		num := strings.TrimSuffix(strings.TrimSuffix(s, "mbit"), "m")
		mb, err := strconv.ParseFloat(strings.TrimSpace(num), 64)
		if err != nil {
			return "", fmt.Errorf("invalid mbit: %v", err)
		}
		mb += 2
		return fmt.Sprintf("%.0fmbit", mb), nil
	}
	if v, err := strconv.ParseFloat(s, 64); err == nil {
		v += 2
		return fmt.Sprintf("%.0fmbit", v), nil
	}
	return "", fmt.Errorf("unrecognized rate: %s", in)
}

// -------- prio 生成（按端口派生） --------
func prioBaseForPort(port int) int { return 10000 + (port%5000)*2 }
func priosForPort(port int) (egTCP, egUDP, inTCP, inUDP int) {
	base := prioBaseForPort(port)
	return base, base + 1, base + 2, base + 3
}

// -------- Egress: HTB + u32 (TCP/UDP, sport/dport) --------
func removeEgressFilters(dev string, port int) {
	egTCP, egUDP, _, _ := priosForPort(port)
	_ = runTc("filter", "del", "dev", dev, "parent", "1:", "protocol", "ip", "prio", strconv.Itoa(egTCP))
	_ = runTc("filter", "del", "dev", dev, "parent", "1:", "protocol", "ip", "prio", strconv.Itoa(egUDP))
}

func applyEgressHTB(dev string, port int, rateMbit string) error {
	if err := ensureHTBRoot(dev); err != nil {
		return fmt.Errorf("ensure htb root: %v", err)
	}
	// 先删旧过滤器，防止多条叠加
	removeEgressFilters(dev, port)

	classid := classIDFromPort(port)
	if err := runTc("class", "replace", "dev", dev, "parent", "1:",
		"classid", classid, "htb", "rate", rateMbit, "ceil", rateMbit); err != nil {
		// 若 parent 1: 不存在，ensure 后再试（双保险）
		if strings.Contains(strings.ToLower(err.Error()), "no such file") {
			if e2 := ensureHTBRoot(dev); e2 != nil {
				return fmt.Errorf("ensure htb root retry: %v", e2)
			}
			if e3 := runTc("class", "replace", "dev", dev, "parent", "1:",
				"classid", classid, "htb", "rate", rateMbit, "ceil", rateMbit); e3 != nil {
				return e3
			}
		} else {
			return err
		}
	}

	p := strconv.Itoa(port)
	egTCP, egUDP, _, _ := priosForPort(port)

	// TCP dport / sport
	_ = runTc("filter", "replace", "dev", dev, "parent", "1:",
		"protocol", "ip", "prio", strconv.Itoa(egTCP), "u32",
		"match", "ip", "protocol", "6", "0xff",
		"match", "ip", "dport", p, "0xffff",
		"flowid", classid)
	_ = runTc("filter", "replace", "dev", dev, "parent", "1:",
		"protocol", "ip", "prio", strconv.Itoa(egTCP), "u32",
		"match", "ip", "protocol", "6", "0xff",
		"match", "ip", "sport", p, "0xffff",
		"flowid", classid)

	// UDP dport / sport
	_ = runTc("filter", "replace", "dev", dev, "parent", "1:",
		"protocol", "ip", "prio", strconv.Itoa(egUDP), "u32",
		"match", "ip", "protocol", "17", "0xff",
		"match", "ip", "dport", p, "0xffff",
		"flowid", classid)
	_ = runTc("filter", "replace", "dev", dev, "parent", "1:",
		"protocol", "ip", "prio", strconv.Itoa(egUDP), "u32",
		"match", "ip", "protocol", "17", "0xff",
		"match", "ip", "sport", p, "0xffff",
		"flowid", classid)

	return nil
}

func removeEgressHTB(dev string, port int) {
	classid := classIDFromPort(port)
	removeEgressFilters(dev, port)
	_ = runTc("class", "del", "dev", dev, "classid", classid)
}

// -------- Ingress: police (TCP/UDP, dport) --------
func applyIngressPolice(dev string, port int, rateMbit string) error {
	if err := ensureIngress(dev); err != nil {
		return fmt.Errorf("ensure ingress: %v", err)
	}
	// 先删旧（该端口 prio）
	removeIngressPolice(dev, port)

	p := strconv.Itoa(port)
	_, _, inTCP, inUDP := priosForPort(port)

	// TCP
	if err := runTc("filter", "replace", "dev", dev, "parent", "ffff:",
		"protocol", "ip", "prio", strconv.Itoa(inTCP), "u32",
		"match", "ip", "protocol", "6", "0xff",
		"match", "ip", "dport", p, "0xffff",
		"police", "rate", rateMbit, "burst", "300k", "mtu", "64kb", "drop"); err != nil {
		return err
	}
	// UDP
	if err := runTc("filter", "replace", "dev", dev, "parent", "ffff:",
		"protocol", "ip", "prio", strconv.Itoa(inUDP), "u32",
		"match", "ip", "protocol", "17", "0xff",
		"match", "ip", "dport", p, "0xffff",
		"police", "rate", rateMbit, "burst", "300k", "mtu", "64kb", "drop"); err != nil {
		return err
	}
	return nil
}

func removeIngressPolice(dev string, port int) {
	_, _, inTCP, inUDP := priosForPort(port)
	_ = runTc("filter", "del", "dev", dev, "parent", "ffff:", "protocol", "ip", "prio", strconv.Itoa(inTCP))
	_ = runTc("filter", "del", "dev", dev, "parent", "ffff:", "protocol", "ip", "prio", strconv.Itoa(inUDP))
}

// -------- Handlers --------
func limitHandler(w http.ResponseWriter, r *http.Request) {
	var req LimitRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Dev == "" {
		req.Dev = devName
	}
	classid := classIDFromPort(req.Port)

	if req.Port <= 0 || req.Port > 65535 {
		writeJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "invalid port",
			OID: req.OID, Dev: req.Dev, Port: req.Port, Up: req.Up, Down: req.Down, ClassID: classid})
		return
	}
	if req.Up == "" && req.Down == "" {
		writeJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "up or down required",
			OID: req.OID, Dev: req.Dev, Port: req.Port, Up: req.Up, Down: req.Down, ClassID: classid})
		return
	}

	// 关键：Down 为空时默认与 Up 同步，避免旧 police 残留
	if req.Down == "" && req.Up != "" {
		req.Down = req.Up
	}

	var upOut, downOut, downMode string

	// Egress（上行）
	if req.Up != "" {
		norm, err := normalizeRateMbpsPlus2(req.Up)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "invalid up: " + err.Error(),
				OID: req.OID, Dev: req.Dev, Port: req.Port, ClassID: classid})
			return
		}
		if err := applyEgressHTB(req.Dev, req.Port, norm); err != nil {
			writeJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "apply up failed: " + err.Error(),
				OID: req.OID, Dev: req.Dev, Port: req.Port, ClassID: classid})
			return
		}
		upOut = norm
	}

	// Ingress（下行）
	if req.Down != "" {
		norm, err := normalizeRateMbpsPlus2(req.Down)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "invalid down: " + err.Error(),
				OID: req.OID, Dev: req.Dev, Port: req.Port, ClassID: classid})
			return
		}
		if err := applyIngressPolice(req.Dev, req.Port, norm); err != nil {
			writeJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "apply down(police) failed: " + err.Error(),
				OID: req.OID, Dev: req.Dev, Port: req.Port, ClassID: classid})
			return
		}
		downMode = "police"
		downOut = norm
	}

	stateMu.Lock()
	state[req.Port] = req
	stateMu.Unlock()

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true, Message: "limit applied",
		OID: req.OID, Dev: req.Dev, Port: req.Port,
		Up: upOut, Down: downOut, ClassID: classid, DownMode: downMode,
	})
}

func unlimitHandler(w http.ResponseWriter, r *http.Request) {
	var req LimitRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Dev == "" {
		req.Dev = devName
	}
	classid := classIDFromPort(req.Port)

	if req.Port <= 0 || req.Port > 65535 {
		writeJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "invalid port",
			OID: req.OID, Dev: req.Dev, Port: req.Port, ClassID: classid})
		return
	}

	removeIngressPolice(req.Dev, req.Port)
	removeEgressHTB(req.Dev, req.Port)

	stateMu.Lock()
	delete(state, req.Port)
	stateMu.Unlock()

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true, Message: "limit removed",
		OID: req.OID, Dev: req.Dev, Port: req.Port, ClassID: classid,
	})
}

func clearAllHandler(w http.ResponseWriter, r *http.Request) {
	var req ClearAllRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	dev := req.Dev
	if dev == "" {
		dev = devName
	}

	// 清 egress/root
	if err := resetDev(dev); err != nil && !isNotFoundErr(err) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false, "message": err.Error(), "oid": req.OID, "dev": dev,
		})
		return
	}
	// 清 ingress
	_ = runTc("filter", "del", "dev", dev, "parent", "ffff:")
	_ = runTc("qdisc", "del", "dev", dev, "ingress")

	// 清内存状态
	stateMu.Lock()
	for p := range state {
		delete(state, p)
	}
	stateMu.Unlock()

	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true, "message": "all limits cleared", "oid": req.OID, "dev": dev,
	})
}

func listLimitsHandler(w http.ResponseWriter, r *http.Request) {
	stateMu.RLock()
	defer stateMu.RUnlock()

	items := make([]LimitRequest, 0, len(state))
	for _, v := range state {
		items = append(items, v)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"items":   items,
	})
}

func getLimitHandler(w http.ResponseWriter, r *http.Request) {
	portStr := mux.Vars(r)["port"]
	port, _ := strconv.Atoi(portStr)

	stateMu.RLock()
	req, ok := state[port]
	stateMu.RUnlock()

	if !ok {
		writeJSON(w, http.StatusNotFound, APIResponse{
			Success: false, Message: "not found",
			OID: "", Dev: devName, Port: port, ClassID: classIDFromPort(port),
		})
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true, Message: "found",
		OID: req.OID, Dev: req.Dev, Port: req.Port, Up: req.Up, Down: req.Down, ClassID: classIDFromPort(req.Port),
	})
}

// -------- Info & Auth --------
func maskToken(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:4] + "..." + s[len(s)-4:]
}

func getDefaultIPv4() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		return localAddr.IP.String()
	}
	ifaces, _ := net.Interfaces()
	for _, inf := range ifaces {
		addrs, _ := inf.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
				return ipnet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}

func getPublicIP() string {
	out, err := exec.Command("sh", "-c", "curl -fsS ifconfig.me || curl -fsS api.ipify.org || true").Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	return ""
}

func buildURL(host string) string {
	return fmt.Sprintf("http://%s:%s/%s", host, httpPort, strings.TrimPrefix(suffix, "/"))
}

// 更稳健的鉴权：Authorization: Bearer / X-API-Token / ?token=
func requireBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := strings.TrimSpace(apiToken)
		if want == "" {
			next.ServeHTTP(w, r)
			return
		}

		got := ""
		if ah := strings.TrimSpace(r.Header.Get("Authorization")); ah != "" {
			parts := strings.Fields(ah)
			if len(parts) >= 2 && strings.EqualFold(parts[0], "Bearer") {
				got = parts[1]
			}
		}
		if got == "" {
			got = strings.TrimSpace(r.Header.Get("X-API-Token"))
		}
		if got == "" {
			got = strings.TrimSpace(r.URL.Query().Get("token"))
		}

		if got == "" || got != want {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": false,
				"message": "unauthorized: missing or invalid token",
				"hint":    "use 'Authorization: Bearer <API_TOKEN>' or 'X-API-Token' or '?token='",
				"need":    maskToken(want),
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func printInfo(showFullToken bool) {
	localIP := getDefaultIPv4()
	publicIP := getPublicIP()
	if publicIP == "" {
		publicIP = localIP
	}
	tokenShown := apiToken
	if !showFullToken {
		tokenShown = maskToken(apiToken)
	}

	fmt.Println("========== Port-Shaper ==========")
	fmt.Printf("默认出网 IP : %s\n", localIP)
	fmt.Printf("推测公网 IP : %s\n", publicIP)
	fmt.Printf("监听端口   : %s\n", httpPort)
	fmt.Printf("路由前缀   : /%s\n", suffix)
	fmt.Printf("API Token : %s\n", tokenShown)
	fmt.Printf("健康检查   : %s/health\n", buildURL(publicIP))
	fmt.Println("---------------------------------")
	fmt.Println("调用示例（带 Bearer 头）：")
	fmt.Printf("curl -H 'Authorization: Bearer %s' %s/limits\n", apiToken, buildURL(publicIP))
	fmt.Println("=================================")
}

// -------- reset / main --------
func resetDev(dev string) error {
	if err := runTc("qdisc", "del", "dev", dev, "root"); err != nil && !isNotFoundErr(err) {
		return fmt.Errorf("qdisc del: %v", err)
	}
	if err := runTc("qdisc", "add", "dev", dev, "root", "handle", "1:", "htb", "default", "999"); err != nil {
		return fmt.Errorf("qdisc add: %v", err)
	}
	if err := runTc("class", "add", "dev", dev, "parent", "1:", "classid", "1:999",
		"htb", "rate", "10gbit", "ceil", "10gbit"); err != nil {
		return fmt.Errorf("class add default: %v", err)
	}
	return nil
}

func main() {
	if v := os.Getenv("API_TOKEN"); v != "" {
		apiToken = v
	}
	if v := os.Getenv("DEV"); v != "" {
		devName = v
	}
	if v := os.Getenv("PORT"); v != "" {
		httpPort = v
	}
	if v := os.Getenv("SUFFIX"); v != "" {
		suffix = strings.Trim(v, "/")
	} else {
		suffix = "health"
	}

	args := os.Args[1:]

	// 无参数 / info：只打印信息
	if len(args) == 0 || args[0] == "info" {
		showFull := len(args) >= 2 && args[1] == "--show-token"
		printInfo(showFull)
		return
	}

	// 服务模式
	if args[0] == "serve" {
		// 启动时初始化成 HTB 根（告别 fq/fq_codel 混淆）
		ensureBase(devName)

		r := mux.NewRouter()
		api := r.PathPrefix("/" + suffix).Subrouter()
		api.Use(requireBearer)

		// 健康检查
		api.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"message":"ok"}`))
		}).Methods("GET")

		// APIs
		api.HandleFunc("/limit", limitHandler).Methods("POST")
		api.HandleFunc("/unlimit", unlimitHandler).Methods("POST")
		api.HandleFunc("/unlimit_all", clearAllHandler).Methods("POST")
		api.HandleFunc("/limits", listLimitsHandler).Methods("GET")
		api.HandleFunc("/limits/{port}", getLimitHandler).Methods("GET")

		log.Println("API listening on :" + httpPort + " /" + suffix)
		log.Fatal(http.ListenAndServe(":"+httpPort, r))
		return
	}

	// 其余：帮助
	fmt.Println("用法：")
	fmt.Println("  port-shaper                 # 打印信息并退出")
	fmt.Println("  port-shaper info            # 同上")
	fmt.Println("  port-shaper info --show-token  # 打印完整 Token")
	fmt.Println("  port-shaper serve           # 启动 HTTP API 服务")
}
