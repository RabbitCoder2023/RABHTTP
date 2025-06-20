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

func (r *ProcessedHttpResponse) BodyAsString() string {
	if r == nil || r.Body == nil {
		return ""
	}
	return string(r.Body)
}

func newInternalClient(options CustomClientOptions) (*http.Client, error) {
	dialer := &net.Dialer{Timeout: options.ConnectTimeout, KeepAlive: options.KeepAliveDuration}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: options.SkipTLSVerify,
		MinVersion:         options.MinTLSVersion,
		MaxVersion:         options.MaxTLSVersion,
		CipherSuites:       options.CipherSuites,
	}
	if len(options.CipherSuites) > 0 {
		tlsConfig.CipherSuites = options.CipherSuites
	}

	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     options.EnableHTTP2,
		MaxIdleConns:          options.MaxIdleConns,
		IdleConnTimeout:       options.IdleConnTimeout,
		TLSHandshakeTimeout:   options.TLSHandshakeTimeout,
		ExpectContinueTimeout: options.ExpectContinueTimeout,
		ResponseHeaderTimeout: options.ResponseHeaderTimeout,
		DisableKeepAlives:     options.DisableKeepAlives,
		MaxIdleConnsPerHost:   options.MaxIdleConnsPerHost,
		MaxConnsPerHost:       options.MaxConnsPerHost,
		ReadBufferSize:        options.ReadBufferSize,
		WriteBufferSize:       options.WriteBufferSize,
		TLSClientConfig:       tlsConfig,
	}

	if options.UseProxy && len(options.Proxies) > 0 {
		proxyFunc := parseProxyURL(options.Proxies[0])
		if proxyFunc != nil {
			transport.Proxy = proxyFunc
		}
	}

	jar := options.CookieJar
	if jar == nil {
		var err error
		jar, err = cookiejar.New(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create cookie jar: %w", err)
		}
	}

	return &http.Client{
		Transport:     transport,
		Timeout:       options.TotalTimeout,
		Jar:           jar,
		CheckRedirect: options.CheckRedirectFunc,
	}, nil
}

func New(options CustomClientOptions) (*CustomHTTPClient, error) {
	httpClient, err := newInternalClient(options)
	if err != nil {
		return nil, err
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
		interval := time.Second / time.Duration(options.RateLimit)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					// Manejar panic de la goroutine
					if c.opts.EnableDebug {
						log.Printf("[PANIC] Rate limiter goroutine: %v\n%s", r, debug.Stack())
					}
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
		<-c.tokens
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
				} else if c.opts.EnableDebug {
					log.Printf("[attempt %d] error al parsear proxy: %v", attempt+1, err)
				}
			}
		}

		req, err1 := http.NewRequestWithContext(ctx, method, urlStr, body)
		if err1 != nil {
			atomic.AddInt64(&c.Errors, 1)
			return nil, fmt.Errorf("error creando petición: %w", err1)
		}

		for key, vals := range headers {
			for _, v := range vals {
				req.Header.Add(key, v)
			}
		}

		if c.defaultUserAgent != "" && req.Header.Get("User-Agent") == "" {
			req.Header.Add("User-Agent", c.defaultUserAgent)
		}

		rsp, err2 := client.Do(req)

		if err2 == nil && (rsp.StatusCode == 200 || rsp.StatusCode == 302) {
			defer rsp.Body.Close()

			reader := rsp.Body
			if enc := rsp.Header.Get("Content-Encoding"); strings.Contains(enc, "gzip") {
				if gz, gzErr := gzip.NewReader(rsp.Body); gzErr == nil {
					reader = gz
				}
			}
			data, err := io.ReadAll(reader)
			if err == nil {
				return &ProcessedHttpResponse{rsp.StatusCode, rsp.Header, rsp.Cookies(), data, rsp.Request, proxyFinal}, nil
			}
			atomic.AddInt64(&c.Errors, 1)
			lastErr = err
		} else {
			atomic.AddInt64(&c.Retries, 1)
			lastErr = err2
		}

		wait := c.opts.RetryWaitMin + time.Duration(rand.Int63n(int64(c.opts.RetryWaitMax-c.opts.RetryWaitMin)))
		if c.opts.EnableDebug {
			log.Printf("[attempt %d] error: %v, esperando %v", attempt+1, lastErr, wait)
		}
		time.Sleep(wait)
	}

	return nil, fmt.Errorf("fallaron %d intentos: %w", c.opts.RetryCount+1, lastErr)
}

func (c *CustomHTTPClient) Do(ctx context.Context, method, urlStr string, body io.Reader, headers http.Header) (*ProcessedHttpResponse, error) {
	return c.doRequest(ctx, c.client, method, urlStr, body, headers)
}

func (c *CustomHTTPClient) DoNoRedirect(ctx context.Context, method, urlStr string, body io.Reader, headers http.Header) (*ProcessedHttpResponse, error) {
	return c.doRequest(ctx, c.client, method, urlStr, body, headers)
}

// Métodos convenientes
func (c *CustomHTTPClient) Get(ctx context.Context, urlStr string, headers http.Header) (*ProcessedHttpResponse, error) {
	return c.Do(ctx, http.MethodGet, urlStr, nil, headers)
}
func (c *CustomHTTPClient) Post(ctx context.Context, urlStr string, body io.Reader, headers http.Header) (*ProcessedHttpResponse, error) {
	return c.Do(ctx, http.MethodPost, urlStr, body, headers)
}
func (c *CustomHTTPClient) PostNoBody(ctx context.Context, urlStr string, headers http.Header) (*ProcessedHttpResponse, error) {
	return c.Do(ctx, http.MethodPost, urlStr, nil, headers)
}
func (c *CustomHTTPClient) Put(ctx context.Context, urlStr string, body io.Reader, headers http.Header) (*ProcessedHttpResponse, error) {
	return c.Do(ctx, http.MethodPut, urlStr, body, headers)
}
func (c *CustomHTTPClient) Delete(ctx context.Context, urlStr string, body io.Reader, headers http.Header) (*ProcessedHttpResponse, error) {
	return c.Do(ctx, http.MethodDelete, urlStr, body, headers)
}
func (c *CustomHTTPClient) Patch(ctx context.Context, urlStr string, body io.Reader, headers http.Header) (*ProcessedHttpResponse, error) {
	return c.Do(ctx, http.MethodPatch, urlStr, body, headers)
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
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}
