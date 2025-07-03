package RABHTTP

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// Chrome-like fingerprint
	ChromeFingerprint = TLSFingerprint{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		SupportedCurves: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
		SupportedPoints:   []uint8{0}, // uncompressed
		ALPN:              []string{"h2", "http/1.1"},
		SupportedVersions: []uint16{tls.VersionTLS12, tls.VersionTLS13},
	}

	// Firefox-like fingerprint
	FirefoxFingerprint = TLSFingerprint{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		SupportedCurves: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		},
		SupportedPoints:   []uint8{0},
		ALPN:              []string{"h2", "http/1.1"},
		SupportedVersions: []uint16{tls.VersionTLS12, tls.VersionTLS13},
	}

	// Safari-like fingerprint
	SafariFingerprint = TLSFingerprint{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		SupportedCurves: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
		SupportedPoints:   []uint8{0},
		ALPN:              []string{"h2", "http/1.1"},
		SupportedVersions: []uint16{tls.VersionTLS12, tls.VersionTLS13},
	}
)

// TLSFingerprint define un fingerprint TLS personalizado
type TLSFingerprint struct {
	MinVersion        uint16
	MaxVersion        uint16
	CipherSuites      []uint16
	SupportedCurves   []tls.CurveID
	SupportedPoints   []uint8
	ServerName        string
	ALPN              []string
	SupportedVersions []uint16
}

type ProxyConfig struct {
	URLs    []string
	Current int
	mu      sync.RWMutex
	Failed  map[string]time.Time
	Timeout time.Duration
}

func NewProxyConfig(urls []string) *ProxyConfig {
	parsed := make([]string, 0, len(urls))
	for _, entry := range urls {
		p, err := parseProxyEntry(entry)
		if err != nil {
			// Si la cadena es completamente inválida, detenemos la ejecución.
			panic(fmt.Sprintf("proxy inválido %q: %v", entry, err))
		}
		parsed = append(parsed, p)
	}

	return &ProxyConfig{
		URLs:    parsed,
		Failed:  make(map[string]time.Time),
		Timeout: 5 * time.Minute, // Tiempo antes de reintentar proxy fallido
	}
}
func (pc *ProxyConfig) GetProxy() (string, error) {
	if len(pc.URLs) == 0 {
		return "", fmt.Errorf("no hay proxies configurados")
	}

	pc.mu.Lock()
	defer pc.mu.Unlock()

	// Limpiar proxies fallidos que ya pasaron el timeout
	now := time.Now()
	for url, failTime := range pc.Failed {
		if now.Sub(failTime) > pc.Timeout {
			delete(pc.Failed, url)
		}
	}

	// Encontrar un proxy disponible
	for i := 0; i < len(pc.URLs); i++ {
		url := pc.URLs[pc.Current]
		pc.Current = (pc.Current + 1) % len(pc.URLs)

		if _, failed := pc.Failed[url]; !failed {
			return url, nil
		}
	}

	return "", fmt.Errorf("todos los proxies están fallidos")
}

func (pc *ProxyConfig) MarkFailed(url string) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.Failed[url] = time.Now()
}

// Opciones para el cliente HTTP personalizado
type CustomClientOptions struct {
	// Timeouts
	TotalTimeout          time.Duration
	ConnectTimeout        time.Duration
	ResponseHeaderTimeout time.Duration
	TLSHandshakeTimeout   time.Duration
	ExpectContinueTimeout time.Duration
	IdleConnTimeout       time.Duration
	KeepAliveDuration     time.Duration

	// Conexiones
	DisableKeepAlives   bool
	DisableCookies      bool
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	MaxConnsPerHost     int
	EnableHTTP2         bool

	// TLS y Fingerprinting
	TLSFingerprint  *TLSFingerprint
	SkipTLSVerify   bool
	CustomTLSConfig *tls.Config

	// Proxy
	UseProxy    bool
	ProxyConfig *ProxyConfig

	// Cookies y Redirecciones
	CookieJar         http.CookieJar
	CheckRedirectFunc func(req *http.Request, via []*http.Request) error

	// Buffers
	ReadBufferSize  int
	WriteBufferSize int

	// Headers
	DefaultUserAgent string
	DefaultHeaders   map[string]string

	// Control de flujo
	MaxConcurrentRequests int
	RateLimit             int
	RetryCount            int
	RetryWaitMin          time.Duration
	RetryWaitMax          time.Duration
	RetryableStatusCodes  []int

	// Debug
	EnableDebug bool
}

// Valores por defecto
func DefaultOptions() CustomClientOptions {
	return CustomClientOptions{
		TotalTimeout:          60 * time.Second,
		ConnectTimeout:        15 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		KeepAliveDuration:     30 * time.Second,
		MaxIdleConns:          500,
		MaxIdleConnsPerHost:   250,
		MaxConnsPerHost:       250,
		EnableHTTP2:           true,
		TLSFingerprint:        &ChromeFingerprint,
		RetryCount:            5,
		RetryWaitMin:          1 * time.Second,
		RetryWaitMax:          5 * time.Second,
		RetryableStatusCodes:  []int{500, 502, 503, 504, 408, 429},
		ReadBufferSize:        4096,
		WriteBufferSize:       4096,
		DefaultUserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
}

type ProcessedHttpResponse struct {
	StatusCode int
	Headers    http.Header
	Cookies    []*http.Cookie
	Body       []byte
	Request    *http.Request
	ProxyURL   string
	Duration   time.Duration
	Attempts   int
}

type CustomHTTPClient struct {
	client *http.Client
	opts   CustomClientOptions
	sem    chan struct{}
	tokens chan struct{}
	stopCh chan struct{}
	wg     sync.WaitGroup

	// Métricas con atomic
	requests int64
	retries  int64
	errors   int64

	// Mutex para operaciones thread-safe
	mu sync.RWMutex
}

type methodWrapper struct {
	c           *CustomHTTPClient
	noRedirect  bool
	fingerprint *TLSFingerprint
}

func createTLSConfig(fingerprint *TLSFingerprint, skipVerify bool) *tls.Config {
	config := &tls.Config{
		InsecureSkipVerify: skipVerify,
	}

	if fingerprint != nil {
		config.MinVersion = fingerprint.MinVersion
		config.MaxVersion = fingerprint.MaxVersion
		config.CipherSuites = fingerprint.CipherSuites
		config.CurvePreferences = fingerprint.SupportedCurves
		config.NextProtos = fingerprint.ALPN
		config.ServerName = fingerprint.ServerName
	}

	return config
}

func newInternalClient(options CustomClientOptions) (*http.Client, error) {
	// Validaciones
	if options.ConnectTimeout <= 0 {
		return nil, fmt.Errorf("ConnectTimeout debe ser mayor a 0")
	}
	if options.TotalTimeout <= 0 {
		return nil, fmt.Errorf("TotalTimeout debe ser mayor a 0")
	}

	// Configuración del dialer TCP
	dialer := &net.Dialer{
		Timeout:   options.ConnectTimeout,
		KeepAlive: options.KeepAliveDuration,
		DualStack: true,
	}

	// Configuración TLS
	var tlsConfig *tls.Config
	if options.CustomTLSConfig != nil {
		tlsConfig = options.CustomTLSConfig
	} else {
		tlsConfig = createTLSConfig(options.TLSFingerprint, options.SkipTLSVerify)
	}

	// Configuración del transport
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     options.EnableHTTP2,
		MaxIdleConns:          options.MaxIdleConns,
		MaxIdleConnsPerHost:   options.MaxIdleConnsPerHost,
		MaxConnsPerHost:       options.MaxConnsPerHost,
		IdleConnTimeout:       options.IdleConnTimeout,
		TLSHandshakeTimeout:   options.TLSHandshakeTimeout,
		ExpectContinueTimeout: options.ExpectContinueTimeout,
		ResponseHeaderTimeout: options.ResponseHeaderTimeout,
		DisableKeepAlives:     options.DisableKeepAlives,
		ReadBufferSize:        options.ReadBufferSize,
		WriteBufferSize:       options.WriteBufferSize,
		TLSClientConfig:       tlsConfig,
	}

	// Configuración de proxy
	if options.UseProxy && options.ProxyConfig != nil {
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			proxyURL, err := options.ProxyConfig.GetProxy()
			if err != nil {
				return nil, err
			}
			return url.Parse(proxyURL)
		}
	}

	// Configuración del cookie jar
	var jar http.CookieJar
	if !options.DisableCookies {
		if options.CookieJar != nil {
			jar = options.CookieJar
		} else {
			var err error
			jar, err = cookiejar.New(nil)
			if err != nil {
				return nil, fmt.Errorf("failed to create cookie jar: %w", err)
			}
		}
	}

	// Función de redirección
	checkRedirectFunc := options.CheckRedirectFunc
	if checkRedirectFunc == nil {
		checkRedirectFunc = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			// Propagar headers seguros
			if len(via) > 0 {
				lastReq := via[len(via)-1]
				for key, vals := range lastReq.Header {
					if strings.EqualFold(key, "User-Agent") ||
						strings.HasPrefix(key, "X-") ||
						strings.EqualFold(key, "Authorization") {
						for _, v := range vals {
							req.Header.Set(key, v)
						}
					}
				}
			}
			return nil
		}
	}

	return &http.Client{
		Transport:     transport,
		Timeout:       options.TotalTimeout,
		Jar:           jar,
		CheckRedirect: checkRedirectFunc,
	}, nil
}

func New(options CustomClientOptions) (*CustomHTTPClient, error) {
	// Validaciones
	if options.RateLimit < 0 || options.MaxConcurrentRequests < 0 {
		return nil, fmt.Errorf("valores negativos inválidos en configuración")
	}

	httpClient, err := newInternalClient(options)
	if err != nil {
		return nil, fmt.Errorf("error creando cliente HTTP: %w", err)
	}

	c := &CustomHTTPClient{
		client: httpClient,
		opts:   options,
		stopCh: make(chan struct{}),
	}

	// Semáforo para limitar concurrencia
	if options.MaxConcurrentRequests > 0 {
		c.sem = make(chan struct{}, options.MaxConcurrentRequests)
	}

	// Rate limiter
	if options.RateLimit > 0 {
		c.tokens = make(chan struct{}, options.RateLimit)

		// Llenar tokens iniciales
		for i := 0; i < options.RateLimit; i++ {
			c.tokens <- struct{}{}
		}

		// Goroutine para reponer tokens
		c.wg.Add(1)
		go c.rateLimiterWorker()
	}

	return c, nil
}
func (c *CustomHTTPClient) rateLimiterWorker() {
	defer c.wg.Done()
	defer func() {
		if r := recover(); r != nil && c.opts.EnableDebug {
			log.Printf("[PANIC] Rate limiter: %v\n%s", r, debug.Stack())
		}
	}()

	interval := time.Second
	if c.opts.RateLimit > 1 {
		interval = time.Second / time.Duration(c.opts.RateLimit)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			select {
			case c.tokens <- struct{}{}:
			default:
				// Canal lleno, no hacer nada
			}
		}
	}
}
func (c *CustomHTTPClient) Close() error {
	close(c.stopCh)
	c.wg.Wait()
	return nil
}
func (c *CustomHTTPClient) isRetryableError(err error, statusCode int) bool {
	if err != nil {
		// Errores de red son reintentos
		if strings.Contains(err.Error(), "timeout") ||
			strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "no such host") {
			return true
		}
	}

	// Códigos de estado reintentos
	for _, code := range c.opts.RetryableStatusCodes {
		if statusCode == code {
			return true
		}
	}

	return false
}

func (c *CustomHTTPClient) doRequest(ctx context.Context, client *http.Client, method, urlStr string, body io.Reader, headers http.Header) (*ProcessedHttpResponse, error) {
	startTime := time.Now()
	atomic.AddInt64(&c.requests, 1)

	// Control de concurrencia
	if c.sem != nil {
		select {
		case c.sem <- struct{}{}:
			defer func() { <-c.sem }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Rate limiting
	if c.tokens != nil {
		select {
		case <-c.tokens:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	var lastErr error
	var proxyUsed string

	for attempt := 0; attempt <= c.opts.RetryCount; attempt++ {
		// Crear request
		req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
		if err != nil {
			atomic.AddInt64(&c.errors, 1)
			return nil, fmt.Errorf("error creando petición: %w", err)
		}

		// Aplicar headers
		c.applyHeaders(req, headers)

		// Ejecutar request
		resp, err := client.Do(req)
		if err != nil {
			atomic.AddInt64(&c.errors, 1)
			lastErr = err

			// Marcar proxy como fallido si aplica
			if c.opts.UseProxy && c.opts.ProxyConfig != nil && proxyUsed != "" {
				c.opts.ProxyConfig.MarkFailed(proxyUsed)
			}

			if c.isRetryableError(err, 0) && attempt < c.opts.RetryCount {
				c.waitForRetry(attempt)
				continue
			}
			return nil, fmt.Errorf("error en petición después de %d intentos: %w", attempt+1, err)
		}

		// Procesar respuesta
		processedResp, err := c.processResponse(resp, req, proxyUsed, startTime, attempt+1)
		if err != nil {
			resp.Body.Close()
			lastErr = err

			if c.isRetryableError(err, resp.StatusCode) && attempt < c.opts.RetryCount {
				atomic.AddInt64(&c.retries, 1)
				c.waitForRetry(attempt)
				continue
			}
			return nil, fmt.Errorf("error procesando respuesta: %w", err)
		}

		// Verificar si el código de estado es reintentable
		if c.isRetryableError(nil, resp.StatusCode) && attempt < c.opts.RetryCount {
			resp.Body.Close()
			atomic.AddInt64(&c.retries, 1)
			c.waitForRetry(attempt)
			continue
		}

		return processedResp, nil
	}

	return nil, fmt.Errorf("fallaron todos los intentos: %w", lastErr)
}

func (c *CustomHTTPClient) applyHeaders(req *http.Request, headers http.Header) {
	// Headers personalizados
	for key, vals := range headers {
		for _, v := range vals {
			req.Header.Add(key, v)
		}
	}

	// Headers por defecto
	for key, val := range c.opts.DefaultHeaders {
		if req.Header.Get(key) == "" {
			req.Header.Set(key, val)
		}
	}

	// User-Agent por defecto
	if c.opts.DefaultUserAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.opts.DefaultUserAgent)
	}
}
func (c *CustomHTTPClient) processResponse(resp *http.Response, req *http.Request, proxyUsed string, startTime time.Time, attempts int) (*ProcessedHttpResponse, error) {
	defer resp.Body.Close()

	// Manejo de compresión
	var reader io.Reader = resp.Body
	if strings.Contains(resp.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("error creando gzip reader: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	// Leer body
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("error leyendo response body: %w", err)
	}

	// Obtener cookies
	var allCookies []*http.Cookie
	if c.client.Jar != nil && req.URL != nil {
		allCookies = c.client.Jar.Cookies(req.URL)
	} else {
		allCookies = resp.Cookies()
	}

	return &ProcessedHttpResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Cookies:    allCookies,
		Body:       data,
		Request:    resp.Request,
		ProxyURL:   proxyUsed,
		Duration:   time.Since(startTime),
		Attempts:   attempts,
	}, nil
}
func (c *CustomHTTPClient) waitForRetry(attempt int) {
	if c.opts.RetryWaitMin <= 0 {
		return
	}

	wait := c.opts.RetryWaitMin
	if c.opts.RetryWaitMax > c.opts.RetryWaitMin {
		jitter := time.Duration(rand.Int63n(int64(c.opts.RetryWaitMax - c.opts.RetryWaitMin)))
		wait += jitter
	}

	if c.opts.EnableDebug {
		log.Printf("[attempt %d] esperando %v antes del retry", attempt+1, wait)
	}

	time.Sleep(wait)
}

// Aquí agregas estos dos nuevos métodos:
func (c *CustomHTTPClient) Request() *methodWrapper {
	return &methodWrapper{c: c, noRedirect: false}
}

func (c *CustomHTTPClient) RequestNoRedirect() *methodWrapper {
	return &methodWrapper{c: c, noRedirect: true}
}
func (c *CustomHTTPClient) RequestWithFingerprint(fingerprint *TLSFingerprint) *methodWrapper {
	return &methodWrapper{c: c, noRedirect: false, fingerprint: fingerprint}
}

func (c *CustomHTTPClient) Do(ctx context.Context, method, urlStr string, body io.Reader, headers http.Header) (*ProcessedHttpResponse, error) {
	return c.doRequest(ctx, c.client, method, urlStr, body, headers)
}

func (c *CustomHTTPClient) DoNoRedirect(ctx context.Context, method, urlStr string, body io.Reader, headers http.Header) (*ProcessedHttpResponse, error) {
	// Clonamos el cliente para no alterar el original
	clientCopy := *c.client
	clientCopy.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // Detener redirecciones
	}
	return c.doRequest(ctx, &clientCopy, method, urlStr, body, headers)
}

func (c *CustomHTTPClient) DoWithFingerprint(ctx context.Context, method, urlStr string, body io.Reader, headers http.Header, fingerprint *TLSFingerprint) (*ProcessedHttpResponse, error) {
	if fingerprint == nil {
		return c.Do(ctx, method, urlStr, body, headers)
	}

	// Crear cliente temporal con fingerprint personalizado
	opts := c.opts
	opts.TLSFingerprint = fingerprint

	tempClient, err := newInternalClient(opts)
	if err != nil {
		return nil, fmt.Errorf("error creando cliente temporal: %w", err)
	}

	return c.doRequest(ctx, tempClient, method, urlStr, body, headers)
}
func (mw *methodWrapper) Get(ctx context.Context, urlStr string, headers http.Header) (*ProcessedHttpResponse, error) {
	if mw.fingerprint != nil {
		return mw.c.DoWithFingerprint(ctx, http.MethodGet, urlStr, nil, headers, mw.fingerprint)
	}
	if mw.noRedirect {
		return mw.c.DoNoRedirect(ctx, http.MethodGet, urlStr, nil, headers)
	}
	return mw.c.Do(ctx, http.MethodGet, urlStr, nil, headers)
}

func (mw *methodWrapper) Post(ctx context.Context, urlStr string, body io.Reader, headers http.Header) (*ProcessedHttpResponse, error) {
	if mw.fingerprint != nil {
		return mw.c.DoWithFingerprint(ctx, http.MethodPost, urlStr, body, headers, mw.fingerprint)
	}
	if mw.noRedirect {
		return mw.c.DoNoRedirect(ctx, http.MethodPost, urlStr, body, headers)
	}
	return mw.c.Do(ctx, http.MethodPost, urlStr, body, headers)
}

func (mw *methodWrapper) PostNoBody(ctx context.Context, urlStr string, headers http.Header) (*ProcessedHttpResponse, error) {
	return mw.Post(ctx, urlStr, nil, headers)
}

func (mw *methodWrapper) Put(ctx context.Context, urlStr string, body io.Reader, headers http.Header) (*ProcessedHttpResponse, error) {
	if mw.fingerprint != nil {
		return mw.c.DoWithFingerprint(ctx, http.MethodPut, urlStr, body, headers, mw.fingerprint)
	}
	if mw.noRedirect {
		return mw.c.DoNoRedirect(ctx, http.MethodPut, urlStr, body, headers)
	}
	return mw.c.Do(ctx, http.MethodPut, urlStr, body, headers)
}

func (mw *methodWrapper) Delete(ctx context.Context, urlStr string, body io.Reader, headers http.Header) (*ProcessedHttpResponse, error) {
	if mw.fingerprint != nil {
		return mw.c.DoWithFingerprint(ctx, http.MethodDelete, urlStr, body, headers, mw.fingerprint)
	}
	if mw.noRedirect {
		return mw.c.DoNoRedirect(ctx, http.MethodDelete, urlStr, body, headers)
	}
	return mw.c.Do(ctx, http.MethodDelete, urlStr, body, headers)
}

func (mw *methodWrapper) Patch(ctx context.Context, urlStr string, body io.Reader, headers http.Header) (*ProcessedHttpResponse, error) {
	if mw.fingerprint != nil {
		return mw.c.DoWithFingerprint(ctx, http.MethodPatch, urlStr, body, headers, mw.fingerprint)
	}
	if mw.noRedirect {
		return mw.c.DoNoRedirect(ctx, http.MethodPatch, urlStr, body, headers)
	}
	return mw.c.Do(ctx, http.MethodPatch, urlStr, body, headers)
}

// Métodos auxiliares
func (r *ProcessedHttpResponse) BodyAsString() string {
	if r == nil || r.Body == nil {
		return ""
	}
	return string(r.Body)
}

func (r *ProcessedHttpResponse) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

func (r *ProcessedHttpResponse) IsRedirect() bool {
	return r.StatusCode >= 300 && r.StatusCode < 400
}

func (r *ProcessedHttpResponse) IsClientError() bool {
	return r.StatusCode >= 400 && r.StatusCode < 500
}

func (r *ProcessedHttpResponse) IsServerError() bool {
	return r.StatusCode >= 500
}

// Utilidades para cookies
func CookiesToString(cookies []*http.Cookie) string {
	if len(cookies) == 0 {
		return ""
	}
	parts := make([]string, len(cookies))
	for i, c := range cookies {
		parts[i] = fmt.Sprintf("%s=%s", c.Name, c.Value)
	}
	return strings.Join(parts, "; ")
}

func GetCookieValue(cookies []*http.Cookie, name string) string {
	cookie := GetCookie(cookies, name)
	if cookie != nil {
		return cookie.Value
	}
	return ""
}

// Métricas del cliente
func (c *CustomHTTPClient) GetMetrics() map[string]int64 {
	return map[string]int64{
		"requests": atomic.LoadInt64(&c.requests),
		"retries":  atomic.LoadInt64(&c.retries),
		"errors":   atomic.LoadInt64(&c.errors),
	}
}

func (c *CustomHTTPClient) ResetMetrics() {
	atomic.StoreInt64(&c.requests, 0)
	atomic.StoreInt64(&c.retries, 0)
	atomic.StoreInt64(&c.errors, 0)
}

func parseProxyEntry(entry string) (string, error) {
	parts := strings.Split(entry, ":")
	if len(parts) < 2 {
		return "", fmt.Errorf("formato inválido de proxy: %q", entry)
	}
	host, port := parts[0], parts[1]

	var user, pass string
	if len(parts) >= 4 {
		user, pass = parts[2], parts[3]
	}

	if user != "" && pass != "" {
		return fmt.Sprintf("http://%s:%s@%s:%s", user, pass, host, port), nil
	}
	return fmt.Sprintf("http://%s:%s", host, port), nil
}

// Obtiene los Cookies por su Nombre
func GetCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for i := len(cookies) - 1; i >= 0; i-- {
		if cookies[i].Name == name {
			return cookies[i]
		}
	}
	return nil
}
