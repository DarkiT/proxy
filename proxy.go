package proxy

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

var (
	tinyBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 1*1024)
		},
	}
	smallBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 8*1024)
		},
	}
	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 64*1024)
		},
	}
	tlsConfig = loadCertificate()
)

// config 配置结构
type config struct {
	MixedPort      int
	MaxConnections int
	IdleTimeout    time.Duration
	DNS            dnsConfig
	Credentials    map[string]string // username -> password
	AuthEnabled    bool
	TLSEnabled     bool
	CertFile       string
	KeyFile        string
}

// dnsConfig DNS配置结构
type dnsConfig struct {
	Servers  []string
	CacheTTL time.Duration
}

// DefaultConfig 默认配置
var DefaultConfig = config{
	MixedPort:      1080,
	MaxConnections: 1000,
	IdleTimeout:    5 * time.Minute,
	DNS: dnsConfig{
		Servers: []string{
			"8.8.8.8:53",
			"119.29.29.29:53",
		},
		CacheTTL: 10 * time.Minute,
	},
	Credentials: make(map[string]string),
}

// hub 代理服务器的核心结构
type hub struct {
	ctx        context.Context
	cancel     context.CancelFunc
	config     *config
	listener   *listener
	resolver   resolver
	dnsCache   map[string]dnsEntry
	dnsCacheMu sync.RWMutex
	connPool   *connPool
	running    bool
	runningMu  sync.Mutex
	logger     Logger
}

// 内部接口和结构体定义
type resolver interface {
	lookupIP(ctx context.Context, host string) ([]netip.Addr, error)
}

type customResolver struct {
	servers []string
	client  *net.Resolver
}

type cachedResolver struct {
	resolver
	hub *hub
}

type dnsEntry struct {
	ips      []netip.Addr
	expireAt time.Time
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
	mutex  sync.Mutex
}

type proxy interface {
	handle(ctx context.Context, conn net.Conn, head []byte)
}

type httpProxy struct {
	dialer *customDialer
	config *config
}

type socksProxy struct {
	dialer *customDialer
	config *config
}

type listener struct {
	listener net.Listener
	tunnel   *tunnel
	ctx      context.Context
	sem      chan struct{}
}

type tunnel struct {
	httpProxy  proxy
	socksProxy proxy
}

type customDialer struct {
	resolver resolver
	dialer   *net.Dialer
}

// Option 定义配置选项函数类型
type Option func(*config)

// WithPort 设置代理服务器端口
func WithPort(port int) Option {
	return func(c *config) {
		c.MixedPort = port
	}
}

// WithMaxConnections 设置最大连接数
func WithMaxConnections(max int) Option {
	return func(c *config) {
		c.MaxConnections = max
	}
}

// WithIdleTimeout 设置空闲超时时间
func WithIdleTimeout(timeout time.Duration) Option {
	return func(c *config) {
		c.IdleTimeout = timeout
	}
}

// WithDNSServers 设置DNS服务器
func WithDNSServers(servers ...string) Option {
	return func(c *config) {
		c.DNS.Servers = servers
	}
}

// WithLogger 设置logger
func WithLogger(l Logger) Option {
	return func(c *config) {
		if l == nil {
			return
		}
		defaultLogger = l
	}
}

// WithAuth 设置初始认证信息
func WithAuth(username, password string) Option {
	return func(c *config) {
		if c.Credentials == nil {
			c.Credentials = make(map[string]string)
		}
		c.Credentials[username] = password
		c.AuthEnabled = true
	}
}

// WithTLS 添加 TLS 支持
func WithTLS() Option {
	return func(c *config) {
		c.TLSEnabled = true
	}
}

// WithTLSConfig 添加 TLS 配置选项
func WithTLSConfig(certFile, keyFile string) Option {
	return func(c *config) {
		c.TLSEnabled = true
		c.CertFile = certFile
		c.KeyFile = keyFile
	}
}

// NewHub 创建新的代理服务器实例
func NewHub(opts ...Option) *hub {
	config := DefaultConfig

	// 应用所有选项
	for _, opt := range opts {
		opt(&config)
	}

	hub := &hub{
		config:   &config,
		dnsCache: make(map[string]dnsEntry),
		connPool: newConnPool(100),
	}

	// 设置默认 logger
	hub.logger = &logger{
		logger: slog.Default(),
	}

	return hub
}

// SetDNS 添加设置DNS的方法
func (h *hub) SetDNS(servers ...string) error {
	h.runningMu.Lock()
	defer h.runningMu.Unlock()

	if h.running {
		return fmt.Errorf("cannot change DNS servers while proxy is running")
	}

	if len(servers) == 0 {
		return fmt.Errorf("at least one DNS server is required")
	}

	// 验证DNS服务器地址格式
	for _, server := range servers {
		if _, _, err := net.SplitHostPort(server); err != nil {
			return fmt.Errorf("invalid DNS server address: %s", server)
		}
	}

	h.config.DNS.Servers = servers
	return nil
}

// Start 启动代理服务
func (h *hub) Start() error {
	h.runningMu.Lock()
	defer h.runningMu.Unlock()

	if h.running {
		return fmt.Errorf("hub is already running")
	}

	h.ctx, h.cancel = context.WithCancel(context.Background())
	if err := h.initDNS(); err != nil {
		return fmt.Errorf("failed to initialize DNS: %w", err)
	}

	listener, err := newListener(h.ctx, fmt.Sprintf(":%d", h.config.MixedPort), newTunnel(h.createDialer(), h.config), h.config)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	h.listener = listener

	go func() {
		if err := h.listener.run(); err != nil {
			GetLogger().Errorf("Listener failed: %v", err)
		}
	}()

	go h.cleanupDNSCache(h.ctx)

	h.running = true
	GetLogger().Infof("Mixed proxy server listening on port %d", h.config.MixedPort)
	return nil
}

// Stop 停止代理服务
func (h *hub) Stop() error {
	h.runningMu.Lock()
	defer h.runningMu.Unlock()

	if !h.running {
		return fmt.Errorf("hub is not running")
	}

	h.cancel()
	h.running = false
	GetLogger().Infof("Proxy server stopped")
	return nil
}

// Restart 重启代理服务
func (h *hub) Restart() error {
	if err := h.Stop(); err != nil {
		return err
	}
	return h.Start()
}

// Status 获取代理服务状态
func (h *hub) Status() bool {
	return h.running
}

// EnableAuth 动态开启认证
func (h *hub) EnableAuth(username, password string) error {
	h.runningMu.Lock()
	defer h.runningMu.Unlock()

	if username == "" || password == "" {
		return fmt.Errorf("username and password cannot be empty")
	}

	if h.config.Credentials == nil {
		h.config.Credentials = make(map[string]string)
	}
	h.config.Credentials[username] = password
	h.config.AuthEnabled = true

	GetLogger().Infof("Authentication enabled for user: %s", username)
	return nil
}

// DisableAuth 关闭认证
func (h *hub) DisableAuth() {
	h.runningMu.Lock()
	defer h.runningMu.Unlock()

	h.config.Credentials = make(map[string]string)
	h.config.AuthEnabled = false

	GetLogger().Infof("Authentication disabled")
}

// GetAuthStatus 获取认证状态
func (h *hub) GetAuthStatus() (enabled bool, users []string) {
	h.runningMu.Lock()
	defer h.runningMu.Unlock()

	users = make([]string, 0, len(h.config.Credentials))
	for username := range h.config.Credentials {
		users = append(users, username)
	}
	return h.config.AuthEnabled, users
}

// AddCredential 添加新的认证凭据
func (h *hub) AddCredential(username, password string) error {
	h.runningMu.Lock()
	defer h.runningMu.Unlock()

	if username == "" || password == "" {
		return fmt.Errorf("username and password cannot be empty")
	}

	h.config.Credentials[username] = password
	h.config.AuthEnabled = true

	GetLogger().Infof("Added credential for user: %s", username)
	return nil
}

// RemoveCredential 删除认证凭据
func (h *hub) RemoveCredential(username string) error {
	h.runningMu.Lock()
	defer h.runningMu.Unlock()

	if _, exists := h.config.Credentials[username]; !exists {
		return fmt.Errorf("username not found: %s", username)
	}

	delete(h.config.Credentials, username)

	// 如果没有任何凭据，则禁用认证
	if len(h.config.Credentials) == 0 {
		h.config.AuthEnabled = false
	}

	GetLogger().Infof("Removed credential for user: %s", username)
	return nil
}

// ListCredentials 获取所有认证用户
func (h *hub) ListCredentials() []string {
	h.runningMu.Lock()
	defer h.runningMu.Unlock()

	users := make([]string, 0, len(h.config.Credentials))
	for username := range h.config.Credentials {
		users = append(users, username)
	}
	return users
}

// ClearCredentials 清除所有认证
func (h *hub) ClearCredentials() {
	h.runningMu.Lock()
	defer h.runningMu.Unlock()

	h.config.Credentials = make(map[string]string)
	h.config.AuthEnabled = false
	GetLogger().Infof("All credentials cleared")
}

// hub 的内部方法
func (h *hub) initDNS() error {
	r := newResolver(h.config.DNS)
	h.resolver = &cachedResolver{resolver: r, hub: h}
	return nil
}

func (h *hub) createDialer() *customDialer {
	return newCustomDialer(h.resolver)
}

func (h *hub) cleanupDNSCache(ctx context.Context) {
	ticker := time.NewTicker(h.config.DNS.CacheTTL / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			h.dnsCacheMu.Lock()
			for host, entry := range h.dnsCache {
				if now.After(entry.expireAt) {
					delete(h.dnsCache, host)
				}
			}
			h.dnsCacheMu.Unlock()
		}
	}
}

// 内部构造函数
func newCustomDialer(resolver resolver) *customDialer {
	return &customDialer{
		resolver: resolver,
		dialer: &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}
}

func newResolver(cfg dnsConfig) *customResolver {
	if len(cfg.Servers) == 0 {
		cfg.Servers = DefaultConfig.DNS.Servers
	}

	return &customResolver{
		servers: cfg.Servers,
		client: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: time.Second * 5}
				return d.DialContext(ctx, "udp", cfg.Servers[0])
			},
		},
	}
}

func newBufferedConn(conn net.Conn) *bufferedConn {
	return &bufferedConn{
		Conn:   conn,
		reader: bufio.NewReader(conn),
	}
}

func newTunnel(dialer *customDialer, config *config) *tunnel {
	return &tunnel{
		httpProxy:  &httpProxy{dialer: dialer, config: config},
		socksProxy: &socksProxy{dialer: dialer, config: config},
	}
}

func newListener(ctx context.Context, addr string, tunnel *tunnel, config *config) (*listener, error) {
	var l net.Listener
	var err error

	if config.TLSEnabled {
		if config.CertFile != "" && config.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("load certificate error: %v", err)
			}
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{cert},
			}
			l, err = tls.Listen("tcp", addr, tlsConfig)
		} else {
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{loadCertificate()},
			}
			l, err = tls.Listen("tcp", addr, tlsConfig)
		}
	} else {
		l, err = net.Listen("tcp", addr)
	}

	if err != nil {
		return nil, err
	}

	return &listener{
		listener: l,
		tunnel:   tunnel,
		ctx:      ctx,
		sem:      make(chan struct{}, config.MaxConnections),
	}, nil
}

// Listener 方法实现
func (l *listener) run() error {
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		<-l.ctx.Done()
		l.listener.Close()
	}()

	for {
		conn, err := l.listener.Accept()
		if err != nil {
			if l.ctx.Err() != nil {
				break
			}
			GetLogger().Errorf("Failed to accept connection: %v", err)
			continue
		}

		select {
		case l.sem <- struct{}{}:
			go func() {
				defer func() { <-l.sem }()
				l.tunnel.handle(l.ctx, conn)
			}()
		default:
			GetLogger().Warnf("Max connections reached, rejecting new connection")
			conn.Close()
		}
	}

	wg.Wait()
	return nil
}

// Tunnel 方法实现
func (t *tunnel) handle(ctx context.Context, conn net.Conn) {
	bufConn := newBufferedConn(conn)
	head, err := bufConn.peek(1)
	if err != nil {
		if err != io.EOF {
			GetLogger().Errorf("Failed to peek: %v", err)
		}
		conn.Close()
		return
	}

	switch head[0] {
	case 0x04, 0x05:
		t.socksProxy.handle(ctx, bufConn, head)
	default:
		t.httpProxy.handle(ctx, bufConn, head)
	}
}

// HTTP代理实现
func (p *httpProxy) handle(ctx context.Context, conn net.Conn, _ []byte) {
	defer conn.Close()

	bufConn := newBufferedConn(conn)
	peekBytes, err := bufConn.peek(3)
	if err != nil {
		GetLogger().Errorf("Failed to read initial bytes: %v", err)
		return
	}

	// 检查是否是 TLS 握手
	if peekBytes[0] == 0x16 && peekBytes[1] == 0x03 {
		tlsConn := tls.Server(bufConn, &tls.Config{
			Certificates: []tls.Certificate{tlsConfig},
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				return &tls.Config{
					Certificates:       []tls.Certificate{tlsConfig},
					ServerName:         hello.ServerName,
					InsecureSkipVerify: true,
				}, nil
			},
		})
		if err := tlsConn.Handshake(); err != nil {
			GetLogger().Errorf("TLS handshake failed: %v", err)
			return
		}
		bufConn = newBufferedConn(tlsConn)
	}

	req, err := http.ReadRequest(bufConn.reader)
	if err != nil {
		GetLogger().Errorf("Failed to read HTTP request: %v", err)
		return
	}

	// 只在启用认证时才检查认证信息
	if p.config.AuthEnabled {
		auth := req.Header.Get("Proxy-Authorization")
		if !p.validateAuth(auth) {
			resp := "HTTP/1.1 407 Proxy Authentication Required\r\n" +
				"Proxy-Authenticate: Basic realm=\"Proxy\"\r\n" +
				"Content-Length: 0\r\n\r\n"
			conn.Write([]byte(resp))
			return
		}
	}

	if req.Method == http.MethodConnect {
		p.handleHTTPS(ctx, conn, req.Host)
	} else {
		p.handleHTTP(ctx, conn, req)
	}
}

func (p *httpProxy) handleHTTP(ctx context.Context, conn net.Conn, req *http.Request) {
	targetConn, err := p.dialer.DialContext(ctx, "tcp", req.Host)
	if err != nil {
		GetLogger().Errorf("Failed to connect to %s: %v", req.Host, err)
		return
	}
	defer targetConn.Close()

	if err := req.Write(targetConn); err != nil {
		GetLogger().Errorf("Failed to write request: %v", err)
		return
	}

	bidirectionalCopy(ctx, conn, targetConn)
}

func (p *httpProxy) handleHTTPS(ctx context.Context, conn net.Conn, host string) {
	targetConn, err := p.dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		GetLogger().Errorf("Failed to connect to %s: %v", host, err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	_, err = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		GetLogger().Errorf("Failed to write response: %v", err)
		return
	}

	bidirectionalCopy(ctx, conn, targetConn)
}

// SOCKS代理实现
func (p *socksProxy) handle(ctx context.Context, conn net.Conn, head []byte) {
	defer conn.Close()

	var (
		target string
		err    error
	)

	switch head[0] {
	case 0x04:
		target, err = socks4Handshake(conn)
	case 0x05:
		target, err = socks5Handshake(conn, p.config)
	}

	if err != nil {
		GetLogger().Errorf("SOCKS handshake error: %v", err)
		return
	}

	targetConn, err := p.dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		GetLogger().Errorf("Failed to connect to %s: %v", target, err)
		return
	}
	defer targetConn.Close()

	bidirectionalCopy(ctx, conn, targetConn)
}

// 连接相关方法实现
func (c *bufferedConn) Read(b []byte) (int, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.reader.Read(b)
}

func (c *bufferedConn) peek(n int) ([]byte, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.reader.Peek(n)
}

// DialContext DNS相关方法实现
func (d *customDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	ips, err := d.resolver.lookupIP(ctx, host)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, ip := range ips {
		addr := net.JoinHostPort(ip.String(), port)
		conn, err := d.dialer.DialContext(ctx, network, addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no available addresses")
}

func (r *customResolver) lookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	ips, err := r.client.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	result := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if addr, ok := netip.AddrFromSlice(ip.IP); ok {
			result = append(result, addr)
		}
	}
	return result, nil
}

func (r *cachedResolver) lookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	r.hub.dnsCacheMu.RLock()
	if entry, ok := r.hub.dnsCache[host]; ok && time.Now().Before(entry.expireAt) {
		r.hub.dnsCacheMu.RUnlock()
		return entry.ips, nil
	}
	r.hub.dnsCacheMu.RUnlock()

	ips, err := r.resolver.lookupIP(ctx, host)
	if err != nil {
		return nil, err
	}

	r.hub.dnsCacheMu.Lock()
	r.hub.dnsCache[host] = dnsEntry{
		ips:      ips,
		expireAt: time.Now().Add(5 * time.Minute),
	}
	r.hub.dnsCacheMu.Unlock()

	return ips, nil
}

// 工具函数
func bidirectionalCopy(ctx context.Context, conn1, conn2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyConn := func(dst, src net.Conn) {
		defer wg.Done()

		// 根据连接类型智能选择buffer
		var buf []byte
		switch src.(type) {
		case *tls.Conn:
			buf = bufferPool.Get().([]byte)
			defer bufferPool.Put(buf)
		case *bufferedConn:
			buf = smallBufferPool.Get().([]byte)
			defer smallBufferPool.Put(buf)
		default:
			buf = tinyBufferPool.Get().([]byte)
			defer tinyBufferPool.Put(buf)
		}

		// 使用更短的超时时间
		if tc, ok := dst.(interface{ SetWriteDeadline(time.Time) error }); ok {
			tc.SetWriteDeadline(time.Now().Add(15 * time.Second))
		}
		if tc, ok := src.(interface{ SetReadDeadline(time.Time) error }); ok {
			tc.SetReadDeadline(time.Now().Add(15 * time.Second))
		}

		io.CopyBuffer(dst, src, buf)
	}

	go copyConn(conn1, conn2)
	go copyConn(conn2, conn1)

	// 使用 select 监控完成情况
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		conn1.Close()
		conn2.Close()
	case <-done:
	}
}

func socks4Handshake(conn net.Conn) (string, error) {
	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}

	if header[0] != 0x04 {
		return "", fmt.Errorf("invalid SOCKS4 version")
	}

	port := binary.BigEndian.Uint16(header[2:4])
	ip := net.IP(header[4:8])

	var userId []byte
	for {
		b := make([]byte, 1)
		if _, err := conn.Read(b); err != nil {
			return "", err
		}
		if b[0] == 0x00 {
			break
		}
		userId = append(userId, b[0])
	}

	resp := []byte{0x00, 0x5A, header[2], header[3], header[4], header[5], header[6], header[7]}
	if _, err := conn.Write(resp); err != nil {
		return "", err
	}

	return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)), nil
}

func socks5Handshake(conn net.Conn, config *config) (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}

	if header[0] != 0x05 {
		return "", fmt.Errorf("invalid SOCKS5 version")
	}

	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}

	GetLogger().Debugf("Auth enabled: %v, Available methods: %v", config.AuthEnabled, methods)

	// 选择认证方法
	var method byte = 0xFF
	if config.AuthEnabled {
		// 检查是否支持用户名密码认证
		for _, m := range methods {
			if m == 0x02 {
				method = 0x02
				break
			}
		}
	} else {
		// 如果未启用认证，接受无认证方法
		for _, m := range methods {
			if m == 0x00 {
				method = 0x00
				break
			}
		}
	}

	if method == 0xFF {
		return "", fmt.Errorf("no supported auth method")
	}
	// 发送选择的认证方法
	if _, err := conn.Write([]byte{0x05, method}); err != nil {
		return "", err
	}

	GetLogger().Debugf("Selected auth method: %v", method)

	// 如果需要认证，执行认证过程
	if method == 0x02 {
		if err := socks5Auth(conn, config); err != nil {
			return "", err
		}
	}

	// 读取连接请求
	cmd := make([]byte, 4)
	if _, err := io.ReadFull(conn, cmd); err != nil {
		return "", err
	}

	if cmd[0] != 0x05 {
		return "", fmt.Errorf("invalid SOCKS5 version in request")
	}

	if cmd[1] != 0x01 {
		return "", fmt.Errorf("only CONNECT method is supported")
	}

	var host string
	switch cmd[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()
	case 0x03: // Domain name
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return "", err
		}
		domain := make([]byte, length[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		host = string(domain)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()
	default:
		return "", fmt.Errorf("unsupported address type: %d", cmd[3])
	}

	port := make([]byte, 2)
	if _, err := io.ReadFull(conn, port); err != nil {
		return "", err
	}
	portNum := binary.BigEndian.Uint16(port)

	// 发送成功响应
	resp := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(resp); err != nil {
		return "", err
	}

	if host == "" {
		return "", fmt.Errorf("empty host address")
	}

	return net.JoinHostPort(host, fmt.Sprintf("%d", portNum)), nil
}

func socks5Auth(conn net.Conn, config *config) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != 0x01 {
		return fmt.Errorf("invalid auth version")
	}

	userLen := int(header[1])
	username := make([]byte, userLen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}

	passLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLenBuf); err != nil {
		return err
	}
	passLen := int(passLenBuf[0])
	password := make([]byte, passLen)
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	// 验证用户名密码
	storedPassword, exists := config.Credentials[string(username)]
	if exists && storedPassword == string(password) {
		_, err := conn.Write([]byte{0x01, 0x00}) // 认证成功
		return err
	}

	conn.Write([]byte{0x01, 0x01}) // 认证失败
	return fmt.Errorf("invalid credentials")
}

func loadCertificate() tls.Certificate {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Proxy CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10年有效期
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		panic(err)
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privateKey,
	}
}

// 改进连接池实现
type connPool struct {
	pools   map[string]*connectionQueue
	maxIdle int
	maxLife time.Duration
	mu      sync.RWMutex
}

type connectionQueue struct {
	conns chan *poolConn
}

type poolConn struct {
	net.Conn
	createdAt time.Time
}

func newConnPool(maxIdle int) *connPool {
	p := &connPool{
		pools:   make(map[string]*connectionQueue),
		maxIdle: maxIdle,
		maxLife: 5 * time.Minute, // 添加最大连接存活时间
	}
	go p.cleanupStaleConnections()
	return p
}

func (p *connPool) cleanupStaleConnections() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		for key, queue := range p.pools {
			select {
			case conn := <-queue.conns:
				if time.Since(conn.createdAt) > p.maxLife {
					conn.Close()
				} else {
					queue.conns <- conn
				}
			default:
			}
			if len(queue.conns) == 0 {
				delete(p.pools, key)
			}
		}
		p.mu.Unlock()
	}
}

func (p *httpProxy) validateAuth(auth string) bool {
	if !strings.HasPrefix(auth, "Basic ") {
		return false
	}

	payload, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return false
	}

	pair := strings.SplitN(string(payload), ":", 2)
	if len(pair) != 2 {
		return false
	}

	username, password := pair[0], pair[1]
	storedPassword, exists := p.config.Credentials[username]
	return exists && storedPassword == password
}
