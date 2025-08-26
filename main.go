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

// ---- 数据结构 ----
type LimitRequest struct {
	OID  string `json:"oid"`
	Dev  string `json:"dev"`
	Port int    `json:"port"`
	Up   string `json:"up,omitempty"`
	Down string `json:"down,omitempty"`
}

type APIResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`

	OID      string `json:"oid"`
	Dev      string `json:"dev"`
	Port     int    `json:"port"`
	Up       string `json:"up,omitempty"`
	Down     string `json:"down,omitempty"`
	ClassID  string `json:"classid,omitempty"`
	DownMode string `json:"down_mode,omitempty"`
}

// 清空全量
type ClearAllRequest struct {
	OID string `json:"oid"`
	Dev string `json:"dev"`
}

// ---- 运行时状态（内存） ----
var (
	apiToken = "changeme"
	devName  = "eth0"
	httpPort = "8088"
	suffix   = "" // 随机后缀，由环境注入

	stateMu sync.RWMutex
	state   = map[int]LimitRequest{} // 当前规则：key=port
)

// ---- 通用工具 ----
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

// 确保根 qdisc & 默认大口子
func ensureBase(dev string) {
	_ = runTc("qdisc", "del", "dev", dev, "root")
	_ = runTc("qdisc", "add", "dev", dev, "root", "handle", "1:", "htb", "default", "999")
	_ = runTc("class", "add", "dev", dev, "parent", "1:", "classid", "1:999",
		"htb", "rate", "10gbit", "ceil", "10gbit")
}

// 硬重置
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

// 端口 -> classid（十六进制）
func classIDFromPort(port int) string {
	return fmt.Sprintf("1:%x", port)
}

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
func isInUseErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "class in use")
}

// ---- 验证中间件 ----
func requireBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expect := "Bearer " + apiToken
		if r.Header.Get("Authorization") != expect {
			writeJSON(w, http.StatusUnauthorized, APIResponse{
				Success: false, Message: "unauthorized",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---- Handlers ----
// 仅实现上行限速（egress）。下行在容器里多为 policing，裸机可用 IFB 重定向（如需可扩展）
func limitHandler(w http.ResponseWriter, r *http.Request) {
	var req LimitRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Dev == "" {
		req.Dev = devName
	}
	classid := classIDFromPort(req.Port)

	if req.Port <= 0 || req.Port > 65535 {
		writeJSON(w, http.StatusBadRequest, APIResponse{
			Success: false, Message: "invalid port",
			OID: req.OID, Dev: req.Dev, Port: req.Port, Up: req.Up, Down: req.Down, ClassID: classid,
		})
		return
	}
	if req.Up == "" && req.Down == "" {
		writeJSON(w, http.StatusBadRequest, APIResponse{
			Success: false, Message: "up or down required",
			OID: req.OID, Dev: req.Dev, Port: req.Port, Up: req.Up, Down: req.Down, ClassID: classid,
		})
		return
	}

	// 上行：HTB class + u32 filter(s)
	if req.Up != "" {
		if err := runTc("class", "replace", "dev", req.Dev, "parent", "1:",
			"classid", classid, "htb", "rate", req.Up, "ceil", req.Up); err != nil {
			writeJSON(w, http.StatusBadRequest, APIResponse{
				Success: false, Message: err.Error(),
				OID: req.OID, Dev: req.Dev, Port: req.Port, Up: req.Up, Down: req.Down, ClassID: classid,
			})
			return
		}
		p := strconv.Itoa(req.Port)
		_ = runTc("filter", "replace", "dev", req.Dev, "parent", "1:",
			"protocol", "ip", "prio", "1", "u32",
			"match", "ip", "dport", p, "0xffff",
			"flowid", classid)
		_ = runTc("filter", "replace", "dev", req.Dev, "parent", "1:",
			"protocol", "ip", "prio", "1", "u32",
			"match", "ip", "sport", p, "0xffff",
			"flowid", classid)
	}

	downMode := ""
	if req.Down != "" {
		downMode = "police" // 容器内多数场景仅能 police；裸机可扩展 IFB
	}

	stateMu.Lock()
	state[req.Port] = req
	stateMu.Unlock()

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true, Message: "limit applied",
		OID: req.OID, Dev: req.Dev, Port: req.Port, Up: req.Up, Down: req.Down, ClassID: classid, DownMode: downMode,
	})
}

func unlimitHandler(w http.ResponseWriter, r *http.Request) {
	var req LimitRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Dev == "" {
		req.Dev = devName
	}
	classid := classIDFromPort(req.Port)
	p := strconv.Itoa(req.Port)

	if req.Port <= 0 || req.Port > 65535 {
		writeJSON(w, http.StatusBadRequest, APIResponse{
			Success: false, Message: "invalid port",
			OID: req.OID, Dev: req.Dev, Port: req.Port, ClassID: classid,
		})
		return
	}

	errFD := runTc("filter", "del", "dev", req.Dev, "parent", "1:", "protocol", "ip", "prio", "1", "u32",
		"match", "ip", "dport", p, "0xffff")
	errFS := runTc("filter", "del", "dev", req.Dev, "parent", "1:", "protocol", "ip", "prio", "1", "u32",
		"match", "ip", "sport", p, "0xffff")
	errC := runTc("class", "del", "dev", req.Dev, "classid", classid)

	if isInUseErr(errC) {
		_ = runTc("filter", "del", "dev", req.Dev, "parent", "1:", "protocol", "ip", "prio", "1")
		errC = runTc("class", "del", "dev", req.Dev, "classid", classid)
	}

	if isNotFoundErr(errFD) && isNotFoundErr(errFS) && isNotFoundErr(errC) {
		writeJSON(w, http.StatusNotFound, APIResponse{
			Success: false, Message: "not found",
			OID: req.OID, Dev: req.Dev, Port: req.Port, ClassID: classid,
		})
		return
	}
	if (errFD != nil && !isNotFoundErr(errFD)) ||
		(errFS != nil && !isNotFoundErr(errFS)) ||
		(errC != nil && !isNotFoundErr(errC)) {
		var parts []string
		if errFD != nil {
			parts = append(parts, "filter dport: "+errFD.Error())
		}
		if errFS != nil {
			parts = append(parts, "filter sport: "+errFS.Error())
		}
		if errC != nil {
			parts = append(parts, "class: "+errC.Error())
		}
		writeJSON(w, http.StatusBadRequest, APIResponse{
			Success: false, Message: strings.Join(parts, "; "),
			OID: req.OID, Dev: req.Dev, Port: req.Port, ClassID: classid,
		})
		return
	}

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

	stateMu.RLock()
	toClear := make([]int, 0, len(state))
	for p, v := range state {
		if v.Dev == "" || v.Dev == dev {
			toClear = append(toClear, p)
		}
	}
	stateMu.RUnlock()

	if err := resetDev(dev); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success":       false,
			"message":       err.Error(),
			"oid":           req.OID,
			"dev":           dev,
			"cleared_ports": toClear,
			"changed":       len(toClear) > 0,
		})
		return
	}

	stateMu.Lock()
	for _, p := range toClear {
		delete(state, p)
	}
	stateMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":       true,
		"message":       "all limits cleared",
		"oid":           req.OID,
		"dev":           dev,
		"cleared_ports": toClear,
		"changed":       len(toClear) > 0,
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

// ---------- Info ----------
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

	fmt.Println("========== Port-Shaper 信息 ==========")
	fmt.Printf("默认出网 IP : %s\n", localIP)
	fmt.Printf("推测公网 IP : %s\n", publicIP)
	fmt.Printf("监听端口   : %s\n", httpPort)
	fmt.Printf("随机后缀   : %s\n", suffix)
	fmt.Printf("API Token : %s\n", tokenShown)
	fmt.Printf("健康检查   : %s\n", buildURL(publicIP))
	fmt.Println("--------------------------------------")
	fmt.Println("调用示例（带 Bearer 头）：")
	fmt.Printf("curl -H 'Authorization: Bearer %s' %s/limits\n", apiToken, buildURL(publicIP))
	fmt.Println("======================================")
}

// ---- main ----
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

	// 无参数 或 显式 info：打印信息并退出（不进入菜单）
	if len(args) == 0 || args[0] == "info" {
		showFull := false
		if len(args) >= 2 && args[1] == "--show-token" {
			showFull = true
		}
		printInfo(showFull)
		return
	}

	// 服务模式
	if args[0] == "serve" {
		ensureBase(devName)

		r := mux.NewRouter()

		// 所有 API 都挂在 /{suffix} 下
		api := r.PathPrefix("/" + suffix).Subrouter()
		api.Use(requireBearer)

		// 健康检查
		api.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"message":"ok"}`))
		}).Methods("GET")

		api.HandleFunc("/limit", limitHandler).Methods("POST")
		api.HandleFunc("/unlimit", unlimitHandler).Methods("POST")
		api.HandleFunc("/unlimit_all", clearAllHandler).Methods("POST")
		api.HandleFunc("/limits", listLimitsHandler).Methods("GET")
		api.HandleFunc("/limits/{port}", getLimitHandler).Methods("GET")

		log.Println("API listening on :" + httpPort + " /" + suffix)
		log.Fatal(http.ListenAndServe(":"+httpPort, r))
		return
	}

	// 其余参数：帮助
	fmt.Println("用法：")
	fmt.Println("  port-shaper                 # 打印默认信息并退出")
	fmt.Println("  port-shaper info            # 同上")
	fmt.Println("  port-shaper info --show-token  # 打印完整 Token")
	fmt.Println("  port-shaper serve           # 启动 HTTP API 服务")
}
