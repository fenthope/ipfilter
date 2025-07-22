# Touka IP Filter Middleware

一个为 [Touka](https://github.com/infinite-iroha/touka) 框架设计的简单、高效且安全的 IP 地址过滤中间件.

## 特性

-   **黑白名单**: 同时支持白名单 (`AllowList`) 和黑名单 (`BlockList`) 模式.
-   **CIDR 支持**: 列表项可以是单个 IP 地址 (`192.168.1.10`) 或 CIDR 网段 (`10.0.0.0/8`).
-   **高性能**: 所有 IP/CIDR 规则在中间件初始化时**一次性预编译**, 每个请求的匹配操作都通过 `net/netip` 进行极速的位运算, 无任何锁竞争.
-   **灵活配置**: 通过一个简单的 `IPFilterConfig` 结构体即可轻松启用、禁用和配置规则.
-   **Touka 原生集成**: 作为一个标准的 `touka.HandlerFunc`, 可以轻松地应用于全局、路由组或单个路由.

## 安装

```bash
go get github.com/fenthope/ipfilter
```

## 快速上手

以下是一个完整的示例, 展示了如何使用 `ipfilter` 来保护不同的路由组.

```go
// main.go
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/fenthope/ipfilter"
	"github.com/infinite-iroha/touka"
)

func main() {
	r := touka.Default()

	// --- 1. 为管理员区域创建一个严格的白名单过滤器 ---
	// 只有在白名单中的 IP 才能访问 /admin 路由.
	adminFilter, err := ipfilter.NewIPFilter(ipfilter.IPFilterConfig{
		EnableAllowList: true,
		AllowList: []string{
			"127.0.0.1",      // 本地开发
			"192.168.1.0/24", // 公司内网
			"::1",            // 本地开发 (IPv6)
		},
	})
	if err != nil {
		log.Fatalf("Failed to create admin IP filter: %v", err)
	}

	// --- 2. 创建一个全局的黑名单过滤器 ---
	// 阻止已知的恶意 IP 访问除公开页面外的所有路由.
	globalBlockFilter, err := ipfilter.NewIPFilter(ipfilter.IPFilterConfig{
		EnableBlockList: true,
		BlockList: []string{
			"103.224.182.0/24", // 示例: 某个已知的恶意 IP 段
			"198.51.100.10",    // 示例: 某个被封禁的 IP
		},
	})
	if err != nil {
		log.Fatalf("Failed to create global block filter: %v", err)
	}

	// --- 3. 定义路由并应用中间件 ---

	// 公开路由, 不受任何限制.
	r.GET("/", func(c *touka.Context) {
		c.String(http.StatusOK, "Welcome to the public page!")
	})
	
	// 普通用户区域, 应用全局黑名单.
	userRoutes := r.Group("/user")
	userRoutes.Use(globalBlockFilter)
	{
		userRoutes.GET("/profile", func(c *touka.Context) {
			c.String(http.StatusOK, "This is your user profile. Your IP (%s) is not blocked.", c.ClientIP())
		})
	}
	
	// 管理员区域, 同时应用全局黑名单和管理员白名单.
	adminRoutes := r.Group("/admin")
	adminRoutes.Use(globalBlockFilter, adminFilter) // 中间件会按顺序执行
	{
		adminRoutes.GET("/dashboard", func(c *touka.Context) {
			c.String(http.StatusOK, "Welcome, Administrator! Your IP (%s) is whitelisted.", c.ClientIP())
		})
	}

	// --- 4. 运行服务器 ---
	fmt.Println("Server is running on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
```

## 配置

通过 `ipfilter.IPFilterConfig` 结构体进行配置:

| 字段 | 类型 | 描述 | 是否必须 |
| :--- | :--- | :--- | :--- |
| `EnableAllowList` | `bool` | 是否启用白名单模式. | 否 (默认 `false`) |
| `EnableBlockList` | `bool` | 是否启用黑名单模式. | 否 (默认 `false`) |
| `AllowList` | `[]string` | 包含 IP 或 CIDR 的字符串列表. | 如果 `EnableAllowList` 为 `true` |
| `BlockList` | `[]string` | 包含 IP 或 CIDR 的字符串列表. | 如果 `EnableBlockList` 为 `true` |

**注意**: `NewIPFilter` 要求至少启用一种过滤模式 (`EnableAllowList` 或 `EnableBlockList` 必须有一个为 `true`), 并且启用的列表不能为空, 否则会返回错误.

## 过滤规则

中间件的访问控制逻辑遵循以下优先级:

1.  **白名单优先**: 如果白名单 (`EnableAllowList`) 被启用, 则**首先**检查客户端 IP 是否在 `AllowList` 中.
    *   如果**不在**白名单中, 请求将立即被拒绝 (403 Forbidden), 不再进行后续检查.
    *   如果在白名单中, 请求**通过**此阶段, 并继续进行黑名单检查.

2.  **黑名单检查**: 在通过白名单检查 (或白名单被禁用) 后, 如果黑名单 (`EnableBlockList`) 被启用, 则检查客户端 IP 是否在 `BlockList` 中.
    *   如果**在**黑名单中, 请求将被拒绝 (403 Forbidden).
    *   如果不在黑名单中, 请求**通过**此阶段.

3.  **最终放行**: 如果请求通过了所有**已启用**的检查, 它将被允许继续执行后续的路由处理器.