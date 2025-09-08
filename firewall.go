package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/gorilla/mux"
)

// 自定义链
const fwChain = "PS_TRUST"

// 进程内状态：端口 -> 去重后的 IP 集合（空集合表示“该端口全拒绝”）
var (
	fwMu  sync.Mutex
	fwMap = map[int]map[string]struct{}{}
)

// ---------------- 基础工具 ----------------

func isValidIPv4(ip string) bool {
	// 仅单个 IPv4；如需支持 CIDR 可扩展 ParseCIDR
	if strings.Count(ip, ":") > 0 {
		return false
	}
	return net.ParseIP(ip) != nil
}

func ipt(args ...string) error {
	cmd := exec.Command("iptables", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("iptables %v: %s", args, msg)
	}
	return nil
}

func iptExists(args ...string) bool {
	// 使用 -C 检查规则是否存在
	cmd := exec.Command("iptables", append([]string{"-C"}, args...)...)
	return cmd.Run() == nil
}

func ensureChain() error {
	// 创建链（已存在忽略）
	_ = ipt("-N", fwChain)

	// 确保 INPUT 中有一次跳转（插到较前位置）
	// 用 -C 检查，不存在则 -I
	if !iptExists("INPUT", "-j", fwChain) {
		if err := ipt("-I", "INPUT", "-j", fwChain); err != nil {
			return err
		}
	}
	return nil
}

// 确保端口兜底 DROP 存在（TCP/UDP 各一条，位于链尾部）
func ensurePortDrops(port int) error {
	p := strconv.Itoa(port)

	// TCP
	if !iptExists(fwChain, "-p", "tcp", "--dport", p, "-j", "DROP") {
		// 用 -A 追加，保证在 ACCEPT 之后
		if err := ipt("-A", fwChain, "-p", "tcp", "--dport", p, "-j", "DROP"); err != nil {
			return err
		}
	}
	// UDP
	if !iptExists(fwChain, "-p", "udp", "--dport", p, "-j", "DROP") {
		if err := ipt("-A", fwChain, "-p", "udp", "--dport", p, "-j", "DROP"); err != nil {
			return err
		}
	}
	return nil
}

// 删除某端口下的所有 ACCEPT（仅清 ACCEPT，不动兜底 DROP）
func clearAcceptRules(port int) {
	p := strconv.Itoa(port)
	old := fwMap[port]
	for ip := range old {
		_ = ipt("-D", fwChain, "-p", "tcp", "-s", ip, "--dport", p, "-j", "ACCEPT")
		_ = ipt("-D", fwChain, "-p", "udp", "-s", ip, "--dport", p, "-j", "ACCEPT")
	}
}

// 将端口的允许来源替换为 ips：
// - 永远保证兜底 DROP 存在（从而实现“默认全拒绝”）
// - 先清旧的 ACCEPT，再插入新的 ACCEPT（插链首，优先匹配）
// - ips 为空 => 仅保留兜底 DROP，等价“该端口全拒绝”
func replacePortIPs(port int, ips []string) error {
	if err := ensureChain(); err != nil {
		return err
	}
	if err := ensurePortDrops(port); err != nil {
		return err
	}

	// 1) 清旧 ACCEPT
	clearAcceptRules(port)

	// 2) 空数组 => 不再添加 ACCEPT，端口保持“全拒绝”
	if len(ips) == 0 {
		fwMap[port] = map[string]struct{}{} // 空集，表示受管且全拒
		return nil
	}

	// 3) 去重 & 校验
	newSet := map[string]struct{}{}
	clean := make([]string, 0, len(ips))
	for _, raw := range ips {
		ip := strings.TrimSpace(raw)
		if ip == "" {
			continue
		}
		if !isValidIPv4(ip) {
			return fmt.Errorf("invalid ip: %q", ip)
		}
		if _, ok := newSet[ip]; ok {
			continue
		}
		newSet[ip] = struct{}{}
		clean = append(clean, ip)
	}
	sort.Strings(clean)

	// 4) 添加新的 ACCEPT（插到链首，确保优先于兜底 DROP）
	p := strconv.Itoa(port)
	for _, ip := range clean {
		// TCP
		if err := ipt("-I", fwChain, "1", "-p", "tcp", "-s", ip, "--dport", p, "-j", "ACCEPT"); err != nil {
			return err
		}
		// UDP
		if err := ipt("-I", fwChain, "1", "-p", "udp", "-s", ip, "--dport", p, "-j", "ACCEPT"); err != nil {
			return err
		}
	}

	// 5) 更新内存
	fwMap[port] = newSet
	return nil
}

// ---------------- HTTP 层 ----------------

type fwSetReq struct {
	IPs []string `json:"ips"` // 非空=替换放行列表；空=清空放行（保持兜底 DROP）
}

type fwResp struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// POST /firewalls/{port}   设定（set）该端口的可信来源；空数组=全拒
func fwPostSet(w http.ResponseWriter, r *http.Request) {
	ps := mux.Vars(r)["port"]
	port, _ := strconv.Atoi(ps)
	if port <= 0 || port > 65535 {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(fwResp{Success: false, Message: "invalid port"})
		return
	}
	var req fwSetReq
	_ = json.NewDecoder(r.Body).Decode(&req)

	fwMu.Lock()
	err := replacePortIPs(port, req.IPs)
	fwMu.Unlock()

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(fwResp{Success: false, Message: err.Error()})
		return
	}
	msg := "set ok (default deny)"
	if len(req.IPs) == 0 {
		msg = "now fully denied (no IPs allowed)"
	}
	_ = json.NewEncoder(w).Encode(fwResp{Success: true, Message: msg})
}

// GET /firewalls/{port}   查看该端口的允许 IP（空数组表示该端口当前“全拒绝”）
func fwGetByPort(w http.ResponseWriter, r *http.Request) {
	ps := mux.Vars(r)["port"]
	port, _ := strconv.Atoi(ps)
	if port <= 0 || port > 65535 {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(fwResp{Success: false, Message: "invalid port"})
		return
	}

	fwMu.Lock()
	set := fwMap[port]
	fwMu.Unlock()

	ips := make([]string, 0, len(set))
	for ip := range set {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	_ = json.NewEncoder(w).Encode(fwResp{
		Success: true,
		Message: "ok",
		Data: map[string]any{
			"port":        port,
			"ips":         ips,
			"defaultDeny": true,
		},
	})
}

// GET /firewalls  查看所有端口与其允许 IP（某端口空数组=该端口“全拒绝”）
func fwGetAll(w http.ResponseWriter, r *http.Request) {
	type pv struct {
		Port        int      `json:"port"`
		IPs         []string `json:"ips"`
		DefaultDeny bool     `json:"defaultDeny"`
	}
	fwMu.Lock()
	views := make([]pv, 0, len(fwMap))
	for p, set := range fwMap {
		ips := make([]string, 0, len(set))
		for ip := range set {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		views = append(views, pv{Port: p, IPs: ips, DefaultDeny: true})
	}
	fwMu.Unlock()

	sort.Slice(views, func(i, j int) bool { return views[i].Port < views[j].Port })

	_ = json.NewEncoder(w).Encode(fwResp{
		Success: true,
		Message: "ok",
		Data: map[string]any{
			"ports": views,
		},
	})
}
