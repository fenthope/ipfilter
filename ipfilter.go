// ipfilter 提供了一个用于 Touka 框架的 IP 黑白名单过滤中间件.
// 它允许根据 IP 地址或 CIDR 范围来允许或拒绝请求.
//
// 过滤优先级:
// 如果同时启用了白名单和黑名单:
//  1. 首先检查客户端 IP 是否在白名单中.
//     - 如果 IP 不在白名单中，请求将被拒绝.
//  2. 如果 IP 在白名单中 (即通过了白名单检查)，则继续检查黑名单.
//     - 如果 IP 在黑名单中，请求将被拒绝.
//  3. 如果通过了所有启用的规则，请求将被允许.
package ipfilter

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/infinite-iroha/touka" // 导入 Touka 框架包
)

// IPFilterConfig 配置 IP 过滤中间件的行为.
type IPFilterConfig struct {
	// EnableAllowList 启用白名单模式.
	// 如果启用，只有列出的 IP 地址或 CIDR 范围才被允许 (在检查黑名单之前).
	EnableAllowList bool
	// EnableBlockList 启用黑名单模式.
	// 如果启用，列出的 IP 地址或 CIDR 范围将被拒绝 (在检查白名单之后).
	EnableBlockList bool

	// AllowList 是一个字符串切片，包含要允许的 IP 地址或 CIDR 范围
	// (例如 "192.168.1.10", "10.0.0.0/8", "2001:db8::/32").
	AllowList []string
	// BlockList 是一个字符串切片，包含要拒绝的 IP 地址或 CIDR 范围.
	BlockList []string
}

// ipFilter 结构体存储了预编译的 IP/CIDR 列表和配置选项.
type ipFilter struct {
	allowList []netip.Prefix // 预解析的白名单 IP 前缀.
	blockList []netip.Prefix // 预解析的黑名单 IP 前缀.
}

// NewIPFilter 是 IP 过滤中间件的构造函数.
// 它接收一个 IPFilterConfig 配置对象，并在初始化时解析并验证 IP 地址列表.
// 返回一个 Touka HandlerFunc (可直接用于 Touka.Use()) 和可能发生的错误.
func NewIPFilter(config IPFilterConfig) (touka.HandlerFunc, error) {
	// 验证配置是否至少启用了一种过滤模式.
	if !config.EnableAllowList && !config.EnableBlockList {
		return nil, errors.New("ipfilter: at least one of EnableAllowList or EnableBlockList must be true")
	}

	filter := &ipFilter{}
	var err error

	// 预解析白名单 (如果启用).
	if config.EnableAllowList {
		if len(config.AllowList) == 0 {
			return nil, errors.New("ipfilter: AllowList cannot be empty when EnableAllowList is true")
		}
		filter.allowList, err = parsePrefixes(config.AllowList)
		if err != nil {
			return nil, fmt.Errorf("ipfilter: failed to parse allow list: %w", err)
		}
	}

	// 预解析黑名单 (如果启用).
	if config.EnableBlockList {
		if len(config.BlockList) == 0 {
			return nil, errors.New("ipfilter: BlockList cannot be empty when EnableBlockList is true")
		}
		filter.blockList, err = parsePrefixes(config.BlockList)
		if err != nil {
			return nil, fmt.Errorf("ipfilter: failed to parse block list: %w", err)
		}
	}

	// 返回实际的中间件处理函数.
	return filter.Handle, nil
}

// Handle 是 IP 过滤中间件的处理函数.
// 该函数在每个请求进入时被调用，以根据配置的黑白名单规则检查客户端 IP.
func (f *ipFilter) Handle(c *touka.Context) {
	// 获取客户端 IP 地址.
	// c.ClientIP() 会根据 Touka Engine 的配置（如 X-Forwarded-For 头部）尝试获取真实客户端 IP.
	clientIPStr := c.ClientIP()
	if clientIPStr == "" {
		// 如果无法确定客户端 IP，出于健壮性考虑，记录警告并默认允许访问.
		c.Warnf("ipfilter: could not determine client IP for request %s %s. Allowing access by default.", c.Request.Method, c.Request.URL.Path)
		c.Next()
		return
	}

	// 解析获取到的客户端 IP 地址.
	clientAddr, err := netip.ParseAddr(clientIPStr)
	if err != nil {
		// 如果客户端 IP 解析失败，通常意味着 IP 格式不正确.
		// 记录错误并默认允许访问，以避免因格式问题而阻止合法请求.
		c.Errorf("ipfilter: failed to parse client IP '%s' for request %s %s: %v. Allowing access.", clientIPStr, c.Request.Method, c.Request.URL.Path, err)
		c.Next()
		return
	}

	// --- 优先检查白名单 (如果启用) ---
	if len(f.allowList) > 0 { // 检查列表长度而不是 EnableAllowList 标志，因为 NewIPFilter 会保证一致性
		if !isIPInList(clientAddr, f.allowList) {
			// IP 不在白名单中，拒绝访问.
			c.Warnf("ipfilter: IP %s not in allow list for request %s %s. Blocking access.", clientIPStr, c.Request.Method, c.Request.URL.Path)
			f.denyAccess(c, clientIPStr, "not in allow list")
			return
		}
		c.Debugf("ipfilter: IP %s is in allow list for request %s %s. Continuing to block list check.", clientIPStr, c.Request.Method, c.Request.URL.Path)
	}

	// --- 检查黑名单 (如果启用) ---
	if len(f.blockList) > 0 { // 检查列表长度而不是 EnableBlockList 标志
		if isIPInList(clientAddr, f.blockList) {
			// IP 在黑名单中，拒绝访问.
			c.Warnf("ipfilter: IP %s is in block list for request %s %s. Blocking access.", clientIPStr, c.Request.Method, c.Request.URL.Path)
			f.denyAccess(c, clientIPStr, "in block list")
			return
		}
		c.Debugf("ipfilter: IP %s is not in block list for request %s %s. Allowing access.", clientIPStr, c.Request.Method, c.Request.URL.Path)
	}

	// 如果所有检查都通过，允许请求继续.
	c.Next()
}

// denyAccess 辅助函数，用于在 IP 被拒绝时统一处理响应.
func (f *ipFilter) denyAccess(c *touka.Context, clientIP, reason string) {
	c.ErrorUseHandle(http.StatusForbidden, fmt.Errorf("access denied for IP %s: %s", clientIP, reason))
}

// parsePrefixes 辅助函数，将一个字符串切片 (IPs/CIDRs) 转换为一个 netip.Prefix 切片.
func parsePrefixes(items []string) ([]netip.Prefix, error) {
	if len(items) == 0 {
		return nil, nil // 如果列表为空，直接返回 nil，避免不必要的分配.
	}

	prefixes := make([]netip.Prefix, 0, len(items))
	for _, item := range items {
		// 尝试解析 CIDR 格式.
		prefix, err := netip.ParsePrefix(item)
		if err == nil {
			prefixes = append(prefixes, prefix)
			continue
		}

		// 如果不是 CIDR，尝试解析单个 IP 地址.
		addr, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("invalid IP address or CIDR: %q", item)
		}
		// 将单个 IP 地址转换为其对应的 /32 (IPv4) 或 /128 (IPv6) 前缀.
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes, nil
}

// isIPInList 辅助函数，检查一个 IP 地址是否被任何一个 Prefix 包含.
func isIPInList(ip netip.Addr, list []netip.Prefix) bool {
	for _, prefix := range list {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
