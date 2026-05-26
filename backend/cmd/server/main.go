package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BrightGir/AI-Honeypot/backend/internal/api"
	"github.com/BrightGir/AI-Honeypot/backend/internal/crypto"
	"github.com/BrightGir/AI-Honeypot/backend/internal/decoy"
	"github.com/BrightGir/AI-Honeypot/backend/internal/demo"
	"github.com/BrightGir/AI-Honeypot/backend/internal/gemini"
	"github.com/BrightGir/AI-Honeypot/backend/internal/honeypot"
	"github.com/BrightGir/AI-Honeypot/backend/internal/lobster"
	openaiClient "github.com/BrightGir/AI-Honeypot/backend/internal/openai"
	"github.com/BrightGir/AI-Honeypot/backend/internal/store"
	"github.com/BrightGir/AI-Honeypot/backend/internal/ws"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
)

func main() {
	// Load .env before anything else so LOG_FORMAT / LOG_LEVEL are available
	// when the logger is initialised below.
	_ = godotenv.Load()

	// Configure structured JSON logging for production.
	// In development (LOG_FORMAT=text) use a human-readable text handler.
	var handler slog.Handler
	if getenv("LOG_FORMAT", "json") == "text" {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: logLevel(),
		})
	} else {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: logLevel(),
		})
	}
	slog.SetDefault(slog.New(handler))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Redis
	redisURL := getenv("REDIS_URL", "redis://localhost:6379")
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		slog.Error("redis parse url", "err", err)
		os.Exit(1)
	}
	rdb := redis.NewClient(opt)
	if err := rdb.Ping(ctx).Err(); err != nil {
		slog.Error("redis connect", "err", err)
		os.Exit(1)
	}
	// Log only the host:port — never log the full URL which may contain a password.
	redisHost := opt.Addr
	slog.Info("redis connected", "host", redisHost)
	defer func() { _ = rdb.Close() }()

	// Secret encryption — used to protect integration API keys at rest in Redis.
	// Generate a key with: openssl rand -hex 32
	var enc crypto.SecretEncryptor
	encKeyHex := os.Getenv("SECRET_ENCRYPTION_KEY")
	if encKeyHex == "" {
		slog.Warn("SECRET_ENCRYPTION_KEY is not set; integration secrets will be stored unencrypted. Set this variable in production.")
		// Use the constructor (not the literal) so that the APP_ENV=production
		// guard in NewNoopEncryptor() fires and prevents accidental plaintext
		// storage of secrets in production deployments.
		enc = crypto.NewNoopEncryptor()
	} else {
		e, err := crypto.NewEncryptor(encKeyHex)
		if err != nil {
			slog.Error("invalid SECRET_ENCRYPTION_KEY", "err", err)
			os.Exit(1)
		}
		enc = e
		slog.Info("secret encryption enabled (AES-256-GCM)")
	}

	st := store.NewWithEncryptor(rdb, enc)
	promptsDir := getenv("PROMPTS_DIR", "./prompts")
	if err := st.SeedIfEmpty(ctx, promptsDir); err != nil {
		slog.Warn("seed warning", "err", err)
	}

	// Decoy generator: OpenAI (primary if key set) → Gemini fallback
	var gen decoy.Generator
	var oaiClient *openaiClient.Client

	openaiKey := getenv("OPENAI_API_KEY", "")
	if openaiKey != "" {
		oaiClient = openaiClient.New(openaiKey)
		gen = oaiClient
		slog.Info("decoy generator: OpenAI")
	}

	geminiKey := getenv("GEMINI_API_KEY", "")
	var gc *gemini.Client
	if geminiKey != "" {
		gc, err = gemini.New(ctx, geminiKey)
		if err != nil {
			slog.Warn("gemini init warning", "err", err)
		} else {
			if gen == nil {
				gen = gc
				slog.Info("decoy generator: Gemini")
			} else {
				slog.Info("decoy generator: OpenAI (Gemini available as fallback)")
			}
			defer func() {
				if err := gc.Close(); err != nil {
					slog.Warn("gemini: close error", "err", err)
				}
			}()
		}
	}

	demoMode := getenv("DEMO_MODE", "false") != "false"
	if geminiKey == "" && openaiKey == "" {
		if !demoMode {
			slog.Error("at least one of GEMINI_API_KEY or OPENAI_API_KEY is required")
			os.Exit(1)
		}
		slog.Warn("no AI API key set; decoy generation disabled (running in DEMO_MODE)")
	}

	// Lobster Trap client
	// Use a dedicated LOBSTER_API_KEY when available. Fall back to the AI key
	// only for development convenience; in production each service should have
	// its own credential (principle of least privilege).
	lobsterURL := getenv("LOBSTER_TRAP_URL", "http://localhost:8080")
	lobsterKey := os.Getenv("LOBSTER_API_KEY")
	if lobsterKey == "" {
		lobsterKey = geminiKey
		if lobsterKey == "" {
			lobsterKey = openaiKey
		}
		if lobsterKey != "" {
			slog.Warn("LOBSTER_API_KEY not set; reusing AI provider key — set a dedicated key in production")
		}
	}
	lc := lobster.New(lobsterURL, lobsterKey)

	// WS Hub
	hub := ws.NewHub()
	safeGo(ctx, "heartbeat", func() { hub.StartHeartbeat(ctx) }, cancel)

	// Demo simulator
	sw := honeypot.New(st, gen, hub)
	sim := demo.New(st, hub)
	if demoMode {
		sim.Start(ctx)
		slog.Info("demo attack simulator started")
	}

	// Threshold
	thresholdStr := getenv("HONEYPOT_RISK_THRESHOLD", "0.6")
	threshold, err := strconv.ParseFloat(thresholdStr, 64)
	if err != nil {
		slog.Warn("invalid HONEYPOT_RISK_THRESHOLD value, using default 0.6", "value", thresholdStr)
		threshold = 0.6
	}

	// API key — must be set explicitly; no insecure default in production.
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		slog.Error("API_KEY environment variable is required but not set; refusing to start with an insecure default")
		os.Exit(1)
	}

	// Gin router — use gin.New() so we can configure TrustedProxies explicitly.
	// gin.Default() trusts all proxies by default, making c.ClientIP() spoofable.
	r := gin.New()
	r.Use(gin.Recovery())

	// TRUSTED_PROXIES controls which upstream IPs gin trusts for X-Forwarded-For.
	// "none" → trust nobody (direct internet); "127.0.0.1,::1" → loopback (default).
	trustedProxies := getenv("TRUSTED_PROXIES", "127.0.0.1,::1")
	if trustedProxies == "none" {
		if err := r.SetTrustedProxies(nil); err != nil {
			slog.Warn("failed to clear trusted proxies", "err", err)
		}
	} else {
		if err := r.SetTrustedProxies(strings.Split(trustedProxies, ",")); err != nil {
			slog.Warn("failed to set trusted proxies", "err", err)
		}
	}

	// CORS — wildcard is explicitly disallowed; default to localhost:3000
	corsOrigins := strings.Split(getenv("CORS_ORIGINS", "http://localhost:3000"), ",")
	var corsConf cors.Config
	if len(corsOrigins) == 1 && corsOrigins[0] == "*" {
		slog.Warn("CORS_ORIGINS=* is insecure; consider restricting to specific origins")
		corsConf = cors.Config{
			AllowAllOrigins: true,
			AllowMethods:    []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"},
			AllowHeaders:    []string{"Origin", "Content-Type", "X-API-Key", "Authorization"},
		}
	} else {
		corsConf = cors.Config{
			AllowOrigins:     corsOrigins,
			AllowMethods:     []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"},
			AllowHeaders:     []string{"Origin", "Content-Type", "X-API-Key", "Authorization"},
			AllowCredentials: true,
		}
	}
	r.Use(cors.New(corsConf))

	handlers := api.NewHandlers(ctx, st, lc, gen, oaiClient, hub, sw, sim, threshold, promptsDir, corsOrigins, apiKey)
	handlers.Register(r, apiKey)

	port := getenv("PORT", "8081")
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// HTTP server runs in a plain goroutine — safeGo is not appropriate here
	// because a fatal listen error (e.g. port in use) should not be retried.
	fatalCh := make(chan error, 1)
	go func() {
		slog.Info("MIRAGE backend starting", "port", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fatalCh <- err
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-quit:
		slog.Info("shutdown signal received")
	case err := <-fatalCh:
		slog.Error("server exited fatally, initiating shutdown", "err", err)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	cancel()
	sim.Stop()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown", "err", err)
	}
	slog.Info("MIRAGE backend stopped")
}

// logLevel reads LOG_LEVEL env var and returns the corresponding slog.Level.
func logLevel() slog.Level {
	switch strings.ToLower(getenv("LOG_LEVEL", "info")) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

const (
	safeGoMaxRetries = 10
	safeGoBaseDelay  = 1 * time.Second
	safeGoMaxDelay   = 60 * time.Second
)

// safeGo runs fn in a goroutine with panic recovery and exponential-backoff
// restart. onFatal is called (instead of os.Exit) when the panic budget is
// exhausted — pass cancel() to trigger a graceful shutdown.
func safeGo(ctx context.Context, name string, fn func(), onFatal func()) {
	go func() {
		for attempt := 1; attempt <= safeGoMaxRetries; attempt++ {
			if ctx.Err() != nil {
				return
			}

			// panicVal holds the recovered value if fn panics; nil otherwise.
			var panicVal any
			func() {
				defer func() {
					if r := recover(); r != nil {
						panicVal = r
						// Log the panic value here so it is always visible,
						// even if the outer loop decides to give up immediately.
						slog.Error("goroutine panicked", "goroutine", name, "panic", r,
							"attempt", attempt, "max", safeGoMaxRetries)
					}
				}()
				fn()
			}()

			// Context cancelled — clean exit, do not restart.
			if ctx.Err() != nil {
				return
			}

			if attempt >= safeGoMaxRetries {
				slog.Error("goroutine exited too many times, giving up",
					"goroutine", name, "attempts", attempt, "panicked", panicVal != nil)
				if onFatal != nil {
					onFatal()
				}
				return
			}

			delay := safeGoBaseDelay * (1 << attempt)
			if delay > safeGoMaxDelay {
				delay = safeGoMaxDelay
			}
			if panicVal != nil {
				slog.Warn("goroutine panicked, restarting",
					"goroutine", name,
					"delay", delay, "attempt", attempt+1, "max", safeGoMaxRetries)
			} else {
				slog.Warn("goroutine exited unexpectedly, restarting",
					"goroutine", name,
					"delay", delay, "attempt", attempt+1, "max", safeGoMaxRetries)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
	}()
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
