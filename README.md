# Go Proxy Package

一个支持 HTTP、HTTPS 和 SOCKS 协议的轻量级代理服务器包。

## 特性

- 支持 HTTP/HTTPS 代理
- 支持 SOCKS4/SOCKS5 代理
- 支持多用户认证
- 支持 TLS 加密（HTTPS 代理协议）
- 内置 DNS 缓存
- 动态认证管理
- 自动生成 TLS 证书

## 安装

```bash
go get github.com/darkit/proxy
```

## 快速开始

```go
package main

import (
    "github.com/darkit/proxy"
    "log"
)

func main() {
    // 创建默认配置的代理服务器
    hub := proxy.NewHub()
    
    // 启动服务
    if err := hub.Start(); err != nil {
        log.Fatal(err)
    }
    
    // 保持程序运行
    select {}
}
```

## 详细配置

### 创建代理服务器

```go
// 使用默认配置
hub := proxy.NewHub()

// 使用自定义配置
hub := proxy.NewHub(
    proxy.WithPort(1080),                    // 设置端口
    proxy.WithMaxConnections(1000),          // 设置最大连接数
    proxy.WithIdleTimeout(5*time.Minute),    // 设置空闲超时
    proxy.WithDNSServers("8.8.8.8:53"),     // 设置DNS服务器
    proxy.WithAuth("user", "pass"),          // 设置初始认证
    proxy.WithTLS(),                         // 启用TLS（HTTPS代理）
    proxy.WithTLSConfig("cert.pem", "key.pem"), // 使用自定义证书
)
```

### 认证管理

```go
// 添加新用户
hub.AddCredential("newuser", "newpass")

// 删除用户
hub.RemoveCredential("user")

// 获取所有认证用户
users := hub.ListCredentials()

// 清除所有认证
hub.ClearCredentials()

// 获取认证状态
enabled, users := hub.GetAuthStatus()
```

### DNS 配置

```go
// 设置DNS服务器
hub.SetDNS("8.8.8.8:53", "1.1.1.1:53")
```

### 服务控制

```go
// 启动服务
hub.Start()

// 停止服务
hub.Stop()

// 重启服务
hub.Restart()

// 获取服务状态
isRunning := hub.Status()
```

## 配置选项

### WithPort(port int)
设置代理服务器监听端口。
```go
proxy.WithPort(1080)
```

### WithMaxConnections(max int)
设置最大并发连接数。
```go
proxy.WithMaxConnections(1000)
```

### WithIdleTimeout(timeout time.Duration)
设置连接空闲超时时间。
```go
proxy.WithIdleTimeout(5 * time.Minute)
```

### WithDNSServers(servers ...string)
设置DNS服务器列表。
```go
proxy.WithDNSServers("8.8.8.8:53", "1.1.1.1:53")
```

### WithAuth(username, password string)
设置初始认证信息。
```go
proxy.WithAuth("user", "pass")
```

### WithTLS()
启用TLS支持（HTTPS代理协议）。
```go
proxy.WithTLS()
```

### WithTLSConfig(certFile, keyFile string)
使用自定义TLS证书。
```go
proxy.WithTLSConfig("cert.pem", "key.pem")
```

## 客户端配置示例

### HTTP/HTTPS 代理
```go
proxyURL, _ := url.Parse("http://localhost:1080")
client := &http.Client{
    Transport: &http.Transport{
        Proxy: http.ProxyURL(proxyURL),
    },
}
```

### HTTPS代理（TLS加密）
```go
proxyURL, _ := url.Parse("https://localhost:1080")
client := &http.Client{
    Transport: &http.Transport{
        Proxy: http.ProxyURL(proxyURL),
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true, // 如果使用自签名证书
        },
    },
}
```

## 注意事项

1. 默认端口为1080
2. 默认最大连接数为1000
3. 默认空闲超时为5分钟
4. 使用自动生成的TLS证书时，客户端需要配置信任证书或禁用证书验证
5. DNS缓存默认TTL为10分钟

## 许可证

本项目采用 MIT 许可证。查看 [LICENSE](LICENSE) 文件了解更多信息。

## 贡献

欢迎提交 Issue 和 Pull Request！