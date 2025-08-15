package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/go-playground/validator/v10"
	"golang.org/x/time/rate"
)

// ---------------------------
// Globals & Constants
// ---------------------------

var (
	version    = "dev"
	commit     = ""
	date       = ""
	log        *slog.Logger
	validate   = validator.New()
	httpClient = createHTTPClient()
)

// ---------------------------
// Types
// ---------------------------

type config struct {
	crossSeedEnabled bool
	crossSeedURL     string
	crossSeedAPIKey  string
	pushoverEnabled  bool
	pushoverUserKey  string
	pushoverToken    string
}

type releaseInfo struct {
	name     string `validate:"required"`
	infoHash string `validate:"required,infohash"`
	category string `validate:"required"`
	size     int64  `validate:"gt=0"`
	indexer  string `validate:"required,url"`
}

// ---------------------------
// Init
// ---------------------------

func init() {
	err := validate.RegisterValidation("infohash", func(fl validator.FieldLevel) bool {
		hash := fl.Field().String()
		return len(hash) == 40 && isHexString(hash)
	})

	if err != nil {
		panic("Failed to register custom validator: " + err.Error())
	}
}

func isHexString(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

// ---------------------------
// Main Entry
// ---------------------------

func main() {
	configureLogger()

	defer func() {
		if r := recover(); r != nil {
			log.Error("Critical error recovered",
				"panic", r,
				"stack", string(debug.Stack()))
			os.Exit(1)
		}
	}()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Info("Starting torrent notifier",
		"version", version,
		"commit", commit,
		"date", date)

	cfg := loadConfig()
	if err := cfg.Validate(); err != nil {
		log.Error("Invalid configuration", "error", err)
		os.Exit(1)
	}

	if len(os.Args) != 6 {
		log.Error("Invalid arguments",
			"usage", fmt.Sprintf("%s <release_name> <info_hash> <category> <size> <indexer>", os.Args[0]))
		os.Exit(1)
	}

	if err := run(ctx, os.Args[1:], cfg); err != nil {
		log.Error("Processing failed", "error", err)
		os.Exit(1)
	}

	log.Info("Processing completed successfully")
}

// ---------------------------
// Orchestration
// ---------------------------

func run(ctx context.Context, args []string, cfg *config) error {
	release, err := parseAndValidateReleaseInfo(args)
	if err != nil {
		return fmt.Errorf("invalid input: %w", err)
	}

	// Separate rate limiters
	pushoverLimiter := rate.NewLimiter(rate.Every(5*time.Second), 2)
	crossSeedLimiter := rate.NewLimiter(rate.Every(5*time.Second), 2)

	if cfg.pushoverEnabled {
		if err := handlePushover(ctx, cfg, release, pushoverLimiter); err != nil {
			return fmt.Errorf("pushover notification failed: %w", err)
		}
	}

	if cfg.crossSeedEnabled {
		if err := handleCrossSeed(ctx, cfg, release, crossSeedLimiter); err != nil {
			return fmt.Errorf("cross-seed search failed: %w", err)
		}
	}

	return nil
}

// ---------------------------
// Handlers
// ---------------------------

func handlePushover(ctx context.Context, cfg *config, release *releaseInfo, limiter *rate.Limiter) error {
	if err := limiter.Wait(ctx); err != nil {
		log.WarnContext(ctx, "Rate limit exceeded for Pushover", "error", err)
		return err
	}
	return sendPushoverNotification(ctx, cfg, release)
}

func handleCrossSeed(ctx context.Context, cfg *config, release *releaseInfo, limiter *rate.Limiter) error {
	if err := limiter.Wait(ctx); err != nil {
		log.WarnContext(ctx, "Rate limit exceeded for CrossSeed", "error", err)
		return err
	}
	return searchCrossSeed(ctx, cfg, release)
}

// ---------------------------
// Config
// ---------------------------

func loadConfig() *config {
	return &config{
		crossSeedEnabled: getEnvBool("CROSS_SEED_ENABLED", false),
		crossSeedURL:     os.Getenv("CROSS_SEED_URL"),
		crossSeedAPIKey:  os.Getenv("CROSS_SEED_API_KEY"),
		pushoverEnabled:  getEnvBool("PUSHOVER_ENABLED", false),
		pushoverUserKey:  os.Getenv("PUSHOVER_USER_KEY"),
		pushoverToken:    os.Getenv("PUSHOVER_TOKEN"),
	}
}

func (cfg *config) Validate() error {
	if cfg.pushoverEnabled && (cfg.pushoverUserKey == "" || cfg.pushoverToken == "") {
		return errors.New("pushover enabled but missing credentials")
	}
	if cfg.crossSeedEnabled && (cfg.crossSeedURL == "" || cfg.crossSeedAPIKey == "") {
		return errors.New("cross-seed enabled but missing configuration")
	}
	return nil
}

func getEnvBool(key string, defaultValue bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return defaultValue
	}
	return strings.ToLower(val) == "true"
}

// ---------------------------
// Release parsing
// ---------------------------

func parseAndValidateReleaseInfo(args []string) (*releaseInfo, error) {
	if len(args) != 5 {
		return nil, errors.New("invalid number of arguments (need 5)")
	}

	size, err := strconv.ParseInt(args[3], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid size: %w", err)
	}

	release := &releaseInfo{
		name:     strings.TrimSpace(args[0]),
		infoHash: strings.ToLower(strings.TrimSpace(args[1])),
		category: strings.TrimSpace(args[2]),
		size:     size,
		indexer:  strings.TrimSpace(args[4]),
	}

	if err := validate.Struct(release); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	return release, nil
}

// ---------------------------
// HTTP Client
// ---------------------------

func createHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				},
			},
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 0,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ---------------------------
// Logger
// ---------------------------

func configureLogger() {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     getLogLevel(),
		AddSource: false,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			switch a.Key {
			case slog.LevelKey:
				return slog.Attr{Key: "severity", Value: a.Value}
			case slog.TimeKey:
				return slog.Attr{Key: "timestamp", Value: a.Value}
			case slog.MessageKey:
				return slog.Attr{Key: "message", Value: a.Value}
			}
			return a
		},
	}).WithAttrs([]slog.Attr{
		slog.String("service", "qbittorrent-notifier"),
	})

	log = slog.New(handler)
}

func getLogLevel() slog.Level {
	level := strings.ToUpper(os.Getenv("LOG_LEVEL"))
	switch level {
	case "DEBUG":
		return slog.LevelDebug
	case "INFO":
		return slog.LevelInfo
	case "WARN", "WARNING":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// ---------------------------
// Notification Senders
// ---------------------------

func sendPushoverNotification(ctx context.Context, cfg *config, release *releaseInfo) error {
	message := fmt.Sprintf(
		"<b>%s</b><small>\n<b>Category:</b> %s</small><small>\n<b>Indexer:</b> %s</small><small>\n<b>Size:</b> %s</small>",
		html.EscapeString(strings.TrimSuffix(release.name, ".torrent")),
		html.EscapeString(release.category),
		html.EscapeString(release.indexer),
		humanize.Bytes(uint64(release.size)),
	)

	payload := map[string]string{
		"token":    cfg.pushoverToken,
		"user":     cfg.pushoverUserKey,
		"title":    "Torrent Downloaded",
		"message":  message,
		"priority": "-2",
		"html":     "1",
	}

	return retryOperation(ctx, 3, 2*time.Second, func() error {
		return sendHTTPRequest(
			ctx,
			http.MethodPost,
			"https://api.pushover.net/1/messages.json",
			payload,
			map[string]string{"Content-Type": "application/json"},
			http.StatusOK,
		)
	})
}

func searchCrossSeed(ctx context.Context, cfg *config, release *releaseInfo) error {
	targetURL, err := buildSafeURL(cfg.crossSeedURL, "/api/webhook")
	if err != nil {
		return fmt.Errorf("failed to build safe URL: %w", err)
	}

	data := url.Values{}
	data.Set("infoHash", release.infoHash)
	data.Set("includeSingleEpisodes", "true")

	return retryOperation(ctx, 3, 2*time.Second, func() error {
		return sendHTTPRequest(
			ctx,
			http.MethodPost,
			targetURL,
			data.Encode(),
			map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
				"X-Api-Key":    cfg.crossSeedAPIKey,
			},
			http.StatusNoContent,
		)
	})
}

// ---------------------------
// HTTP Helper
// ---------------------------

func sendHTTPRequest(
	ctx context.Context,
	method string,
	targetURL string,
	body interface{},
	headers map[string]string,
	expectedStatus int,
) error {
	var reqBody io.Reader

	if ct, exists := headers["Content-Type"]; exists {
		switch ct {
		case "application/x-www-form-urlencoded":
			s, ok := body.(string)
			if !ok {
				return fmt.Errorf("form data must be string, got %T", body)
			}
			reqBody = strings.NewReader(s)
		case "application/json":
			jsonData, err := json.Marshal(body)
			if err != nil {
				return fmt.Errorf("failed to marshal JSON: %w", err)
			}
			reqBody = bytes.NewReader(jsonData)
		default:
			return fmt.Errorf("unsupported Content-Type: %s", ct)
		}
	} else {
		if headers == nil {
			headers = make(map[string]string)
		}
		jsonData, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		reqBody = bytes.NewReader(jsonData)
		headers["Content-Type"] = "application/json"
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	log.DebugContext(ctx, "Sending HTTP request",
		"url", targetURL,
		"method", method,
		"headers", redactHeaders(headers))

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.WarnContext(ctx, "Failed to close response body", "error", err)
		}
	}()

	respBody, _ := io.ReadAll(resp.Body)

	log.DebugContext(ctx, "HTTP response received",
		"status", resp.StatusCode,
		"body", redactBody(string(respBody)),
	)

	if resp.StatusCode != expectedStatus {
		return fmt.Errorf("unexpected status %d (expected %d)",
			resp.StatusCode, expectedStatus)
	}

	log.Info("HTTP request was successful")
	return nil
}

// ---------------------------
// Retry Helpers
// ---------------------------

func retryOperation(ctx context.Context, maxAttempts int, initialDelay time.Duration, op func() error) error {
	const maxTotalTimeout = 10 * time.Minute
	ctx, cancel := context.WithTimeout(ctx, maxTotalTimeout)
	defer cancel()

	var err error
	delay := initialDelay

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err = op()
		if err == nil {
			return nil
		}

		if !isRetriableError(err) {
			return err
		}

		if attempt == maxAttempts {
			break
		}

		log.WarnContext(ctx, "Operation attempt failed",
			"attempt", attempt,
			"error", err,
			"retry_in", delay)

		select {
		case <-time.After(delay):
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return fmt.Errorf("operation failed after %d attempts: %w", maxAttempts, err)
}

func isRetriableError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}

	var statusErr interface{ StatusCode() int }
	if errors.As(err, &statusErr) {
		code := statusErr.StatusCode()
		return code == http.StatusTooManyRequests ||
			code >= http.StatusInternalServerError
	}

	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}

// ---------------------------
// Utils
// ---------------------------

func redactHeaders(headers map[string]string) map[string]string {
	safe := make(map[string]string)
	for k, v := range headers {
		if strings.EqualFold(k, "X-Api-Key") {
			safe[k] = "[REDACTED]"
		} else {
			safe[k] = v
		}
	}
	return safe
}

func redactBody(content string) string {
	if strings.Contains(content, "api_key") {
		return "[REDACTED_API_KEY]"
	}
	if strings.Contains(content, "token") {
		return "[REDACTED_TOKEN]"
	}
	if len(content) > 100 {
		return fmt.Sprintf("[TRUNCATED_LEN=%d]", len(content))
	}
	return content
}

func buildSafeURL(baseURL, urlPath string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("invalid URL scheme: %s", u.Scheme)
	}

	if strings.Contains(urlPath, "..") || strings.Contains(urlPath, "//") {
		return "", errors.New("invalid path containing traversal attempt")
	}

	if os.Getenv("ENV") == "production" && u.Scheme != "https" {
		return "", errors.New("insecure scheme in production environment")
	}

	newURL, err := u.Parse(urlPath)
	if err != nil {
		return "", fmt.Errorf("failed to construct safe URL: %w", err)
	}

	if newURL.Host != "" && newURL.Host != u.Host {
		return "", errors.New("host override detected in URL path")
	}

	newURL.Fragment = ""
	newURL.RawPath = ""
	newURL.Path = path.Clean(newURL.Path)

	return newURL.String(), nil
}
