package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/darkit/proxy"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hub := proxy.NewHub(
		proxy.WithPort(8282),
		proxy.WithMaxConnections(2000),
		proxy.WithIdleTimeout(5*time.Minute),
		proxy.WithDNSServers("8.8.8.8:53", "1.1.1.1:53"),
		proxy.WithAuth("123", "123"), // 启用认证
	)
	log := proxy.GetLogger()
	// 启动服务
	if err := hub.Start(); err != nil {
		log.Errorf(err.Error())
		return
	}

	// 禁用认证
	hub.DisableAuth()

	// 示例：检查认证状态
	enabled, username := hub.GetAuthStatus()
	log.Infof("Auth status - enabled: %v, username: %s", enabled, username)

	// 示例：等待10秒动态启用认证
	time.Sleep(10 * time.Second)

	if err := hub.EnableAuth("123", "123"); err != nil {
		log.Errorf("Failed to enable auth: %v", err)
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		log.Infof("Received shutdown signal, initiating graceful shutdown...")
		cancel()
	}()

	<-ctx.Done()
	if err := hub.Stop(); err != nil {
		log.Errorf("Error stopping proxy: %v", err)
	} else {
		log.Infof("Shutdown completed successfully")
	}
}
