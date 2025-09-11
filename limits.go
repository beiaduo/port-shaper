// limits.go
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/gorilla/mux"
)

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

// -------- 运行时状态（与 main 同包共享全局变量 devName 等）--------
var (
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

	// Down 为空时默认与 Up 同步，避免旧 police 残留
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
