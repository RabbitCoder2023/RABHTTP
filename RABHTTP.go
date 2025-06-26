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
	"sync/atomic"
	"time"
)

// Opciones para el cliente HTTP personalizado
type CustomClientOptions struct {
	TotalTimeout          time.Duration
	ConnectTimeout        time.Duration
	ResponseHeaderTimeout time.Duration
	TLSHandshakeTimeout   time.Duration
	ExpectContinueTimeout time.Duration
	IdleConnTimeout       time.Duration
	KeepAliveDuration     time.Duration
	DisableKeepAlives     bool
	DisableCookies        bool
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	MaxConnsPerHost       int
	EnableHTTP2           bool
	UseProxy              bool
	SkipTLSVerify         bool
	MinTLSVersion         uint16
	MaxTLSVersion         uint16
	CipherSuites          []uint16
	Proxies               []string
	CookieJar             http.CookieJar
	CheckRedirectFunc     func(req *http.Request, via []*http.Request) error
	ReadBufferSize        int
	WriteBufferSize       int
	DefaultUserAgent      string

	MaxConcurrentRequests int
	RateLimit             int
	RetryCount            int
	RetryWaitMin          time.Duration
	RetryWaitMax          time.Duration
	EnableDebug           bool
}

type ProcessedHttpResponse struct {
	StatusCode int
	Headers    http.Header
	Cookies    []*http.Cookie
	Body       []byte
	Request    *http.Request
	ProxyURL   string
}

type CustomHTTPClient struct {
	client           *http.Client
	defaultUserAgent string
	sem              chan struct{}
	tokens           chan struct{}
	opts             CustomClientOptions

	// Contadores
	Retries int64
	Errors  int64
}

type methodWrapper struct {
	c          *CustomHTTPClient
	noRedirect bool
}

func newInternalClient(options CustomClientOptions) (*http.Client, error) {
	// Configuración del dialer TCP
	dialer := &net.Dialer{
		Timeout:   options.ConnectTimeout,
		KeepAlive: options.KeepAliveDuration,
		DualStack: true,
	}

	// Configuración TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: options.SkipTLSVerify,
		MinVersion:         options.MinTLSVersion,
		MaxVersion:         options.MaxTLSVersion,
	}

	if len(options.CipherSuites) > 0 {
		tlsConfig.CipherSuites = options.CipherSuites
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

	// Si se activa el uso de proxy
	if options.UseProxy && len(options.Proxies) > 0 {
		proxyFunc := parseProxyURL(options.Proxies[0])
		if proxyFunc != nil {
			transport.Proxy = proxyFunc
		}
	}

	// Configuración del cookie jar si está permitido
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

	// Redirecciones: función personalizada o default
	checkRedirectFunc := options.CheckRedirectFunc
	if checkRedirectFunc == nil {
		checkRedirectFunc = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			// Propagar headers seguros
			for key, vals := range via[len(via)-1].Header {
				if strings.EqualFold(key, "User-Agent") || strings.HasPrefix(key, "X-") {
					for _, v := range vals {
						req.Header.Add(key, v)
					}
				}
			}
			return nil
		}
	}

	// Crear el cliente final
	return &http.Client{
		Transport:     transport,
		Timeout:       options.TotalTimeout,
		Jar:           jar,
		CheckRedirect: checkRedirectFunc,
	}, nil
}

func New(options CustomClientOptions) (*CustomHTTPClient, error) {
	if options.RateLimit < 0 || options.MaxConcurrentRequests < 0 {
		return nil, fmt.Errorf("valores negativos inválidos en configuración")
	}

	httpClient, err := newInternalClient(options)
	if err != nil {
		return nil, fmt.Errorf("error creando cliente HTTP: %w", err)
	}

	c := &CustomHTTPClient{
		client:           httpClient,
		defaultUserAgent: options.DefaultUserAgent,
		opts:             options,
	}

	if options.MaxConcurrentRequests > 0 {
		c.sem = make(chan struct{}, options.MaxConcurrentRequests)
	}

	if options.RateLimit > 0 {
		c.tokens = make(chan struct{}, options.RateLimit)
		for i := 0; i < options.RateLimit; i++ {
			c.tokens <- struct{}{}
		}

		interval := time.Second
		if options.RateLimit > 1 {
			interval = time.Second / time.Duration(options.RateLimit)
		}

		go func() {
			defer func() {
				if r := recover(); r != nil && c.opts.EnableDebug {
					log.Printf("[PANIC] Rate limiter goroutine: %v\n%s", r, debug.Stack())
				}
			}()
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for range ticker.C {
				select {
				case c.tokens <- struct{}{}:
				default:
				}
			}
		}()
	}

	return c, nil
}

func (c *CustomHTTPClient) doRequest(ctx context.Context, client *http.Client, method, urlStr string, body io.Reader, headers http.Header) (*ProcessedHttpResponse, error) {

	if c.sem != nil {
		select {
		case c.sem <- struct{}{}:
			defer func() { <-c.sem }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if c.tokens != nil {
		select {
		case <-c.tokens:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	var lastErr error

	for attempt := 0; attempt <= c.opts.RetryCount; attempt++ {
		var proxyFinal string
		if c.opts.UseProxy && len(c.opts.Proxies) > 0 {
			proxyStr := c.opts.Proxies[rand.Intn(len(c.opts.Proxies))]
			if proxyFunc := parseProxyURL(proxyStr); proxyFunc != nil {
				if proxyURL, err := proxyFunc(nil); err == nil {
					proxyFinal = proxyURL.String()
					if c.opts.EnableDebug {
						log.Printf("[attempt %d] proxy parseado: %s", attempt+1, proxyFinal)
					}
				}
			}
		}

		req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
		if err != nil {
			atomic.AddInt64(&c.Errors, 1)
			return nil, fmt.Errorf("error creando petición: %w", err)
		}

		for key, vals := range headers {
			for _, v := range vals {
				req.Header.Add(key, v)
			}
		}
		if c.defaultUserAgent != "" && req.Header.Get("User-Agent") == "" {
			req.Header.Add("User-Agent", c.defaultUserAgent)
		}

		// Mostrar cookies enviados si hay jar
		if c.opts.EnableDebug && c.client.Jar != nil && req.URL != nil {
			cookies := c.client.Jar.Cookies(req.URL)
			log.Printf("[cookies enviados] %s", CookiesToString(cookies))
		}

		resp, err := client.Do(req)

		if err == nil && (resp.StatusCode == 200 || resp.StatusCode == 201 || resp.StatusCode == 202 || resp.StatusCode == 204 || resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 303 || resp.StatusCode == 304 || resp.StatusCode == 307 || resp.StatusCode == 401) {
			defer resp.Body.Close()

			var reader io.Reader = resp.Body
			if strings.Contains(resp.Header.Get("Content-Encoding"), "gzip") {
				gz, gzErr := gzip.NewReader(resp.Body)
				if gzErr == nil {
					defer gz.Close()
					reader = gz
				}
			}

			data, readErr := io.ReadAll(reader)
			if readErr == nil {
				var allCookies []*http.Cookie
				if client.Jar != nil && req.URL != nil {
					allCookies = client.Jar.Cookies(req.URL)
				} else {
					allCookies = resp.Cookies()
				}
				return &ProcessedHttpResponse{
					StatusCode: resp.StatusCode,
					Headers:    resp.Header,
					Cookies:    allCookies,
					Body:       data,
					Request:    resp.Request,
					ProxyURL:   proxyFinal,
				}, nil
			}
			atomic.AddInt64(&c.Errors, 1)
			lastErr = readErr
		} else {
			atomic.AddInt64(&c.Retries, 1)
			lastErr = err
		}

		wait := c.opts.RetryWaitMin + time.Duration(rand.Int63n(int64(c.opts.RetryWaitMax-c.opts.RetryWaitMin)))
		if c.opts.EnableDebug {
			log.Printf("[attempt %d] error: %v, esperando %v", attempt+1, lastErr, wait)
		}
		time.Sleep(wait)
	}

	return nil, fmt.Errorf("fallaron %d intentos: %w", c.opts.RetryCount+1, lastErr)
}

// Aquí agregas estos dos nuevos métodos:
func (c *CustomHTTPClient) Request() *methodWrapper {
	return &methodWrapper{c: c, noRedirect: false}
}

func (c *CustomHTTPClient) RequestNoRedirect() *methodWrapper {
	return &methodWrapper{c: c, noRedirect: true}
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

func (mw *methodWrapper) Get(ctx context.Context, urlStr string, headers http.Header) (*ProcessedHttpResponse, error) {
	if mw.noRedirect {
		return mw.c.DoNoRedirect(ctx, http.MethodGet, urlStr, nil, headers)
	}
	return mw.c.Do(ctx, http.MethodGet, urlStr, nil, headers)
}

func (mw *methodWrapper) Post(ctx context.Context, urlStr string, body io.Reader, headers http.Header) (*ProcessedHttpResponse, error) {
	if mw.noRedirect {
		return mw.c.DoNoRedirect(ctx, http.MethodPost, urlStr, body, headers)
	}
	return mw.c.Do(ctx, http.MethodPost, urlStr, body, headers)
}

func (mw *methodWrapper) PostNoBody(ctx context.Context, urlStr string, headers http.Header) (*ProcessedHttpResponse, error) {
	if mw.noRedirect {
		return mw.c.DoNoRedirect(ctx, http.MethodPost, urlStr, nil, headers)
	}
	return mw.c.Do(ctx, http.MethodPost, urlStr, nil, headers)
}

func (mw *methodWrapper) Put(ctx context.Context, urlStr string, body io.Reader, headers http.Header) (*ProcessedHttpResponse, error) {
	if mw.noRedirect {
		return mw.c.DoNoRedirect(ctx, http.MethodPut, urlStr, body, headers)
	}
	return mw.c.Do(ctx, http.MethodPut, urlStr, body, headers)
}

func (mw *methodWrapper) Delete(ctx context.Context, urlStr string, body io.Reader, headers http.Header) (*ProcessedHttpResponse, error) {
	if mw.noRedirect {
		return mw.c.DoNoRedirect(ctx, http.MethodDelete, urlStr, body, headers)
	}
	return mw.c.Do(ctx, http.MethodDelete, urlStr, body, headers)
}

func (mw *methodWrapper) Patch(ctx context.Context, urlStr string, body io.Reader, headers http.Header) (*ProcessedHttpResponse, error) {
	if mw.noRedirect {
		return mw.c.DoNoRedirect(ctx, http.MethodPatch, urlStr, body, headers)
	}
	return mw.c.Do(ctx, http.MethodPatch, urlStr, body, headers)
}

func parseProxyURL(proxy string) func(*http.Request) (*url.URL, error) {
	if proxy == "" {
		return nil
	}
	return func(_ *http.Request) (*url.URL, error) {
		return url.Parse(proxy)
	}
}

// Convierte los Cookies obtenidos en string
func CookiesToString(cookies []*http.Cookie) string {
	parts := make([]string, len(cookies))
	for i, c := range cookies {
		parts[i] = fmt.Sprintf("%s=%s", c.Name, c.Value)
	}
	return strings.Join(parts, "; ")
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

func (r *ProcessedHttpResponse) BodyAsString() string {
	if r == nil || r.Body == nil {
		return ""
	}
	return string(r.Body)
}
