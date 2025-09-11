// main.go
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/gorilla/mux"
)

var (
	apiToken = "changeme"
	devName  = "eth0"
	httpPort = "8088"
	suffix   = "health" // 路由前缀（可通过环境变量 SUFFIX 覆盖）
)

// ------- 通用展示 -------
func maskToken(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:4] + "..." + s[len(s)-4:]
}

func buildURL(host string) string {
	return fmt.Sprintf("http://%s:%s/%s", host, httpPort, strings.TrimPrefix(suffix, "/"))
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

// ------- 鉴权中间件 -------
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
			_, _ = w.Write([]byte(fmt.Sprintf(
				`{"success":false,"message":"unauthorized: missing or invalid token","hint":"use 'Authorization: Bearer <API_TOKEN>' or 'X-API-Token' or '?token='","need":"%s"}`,
				maskToken(want),
			)))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ------- reset（复用 limits.go 的 runTc / isNotFoundErr） -------
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

// ------- 入口 -------
func main() {
	// 环境变量
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
		// 初始化 HTB 根（函数在 limits.go 里）
		ensureBase(devName)

		r := mux.NewRouter()
		api := r.PathPrefix("/" + suffix).Subrouter()
		api.Use(requireBearer)

		// 健康检查
		api.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"message":"ok"}`))
		}).Methods("GET")

		// 限速相关 API（handler 在 limits.go 里）
		api.HandleFunc("/limit", limitHandler).Methods("POST")
		api.HandleFunc("/unlimit", unlimitHandler).Methods("POST")
		api.HandleFunc("/unlimit_all", clearAllHandler).Methods("POST")
		api.HandleFunc("/limits", listLimitsHandler).Methods("GET")
		api.HandleFunc("/limits/{port}", getLimitHandler).Methods("GET")

		//可信ip
		api.HandleFunc("/firewalls/{port}", fwPostSet).Methods("POST")
		api.HandleFunc("/firewalls/{port}", fwGetByPort).Methods("GET")
		api.HandleFunc("/firewalls", fwGetAll).Methods("GET")

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
