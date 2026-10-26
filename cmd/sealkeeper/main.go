// Command sealkeeper is the entry point of the SealKeeper distribution.
//
// Sub-commands (D-D.x):
//
//	serve     — run the HTTP server (default)
//	migrate   — apply database migrations (forward-only, FR-H.61)
//	backup    — create or restore backup tarballs (FR-H.53/54)
//	version   — print build metadata
//
// Configuration precedence is documented in internal/config.
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"crypto/rand"

	"github.com/sched75/sealkeeper/internal/admin"
	"github.com/sched75/sealkeeper/internal/audit"
	"github.com/sched75/sealkeeper/internal/branding"
	"github.com/sched75/sealkeeper/internal/config"
	"github.com/sched75/sealkeeper/internal/cryptobox"
	"github.com/sched75/sealkeeper/internal/demo"
	"github.com/sched75/sealkeeper/internal/domains"
	"github.com/sched75/sealkeeper/internal/elevations"
	"github.com/sched75/sealkeeper/internal/httpserver"
	"github.com/sched75/sealkeeper/internal/integrations"
	"github.com/sched75/sealkeeper/internal/libraries"
	"github.com/sched75/sealkeeper/internal/mailer"
	"github.com/sched75/sealkeeper/internal/mailtemplates"
	"github.com/sched75/sealkeeper/internal/policies"
	"github.com/sched75/sealkeeper/internal/smtpconfig"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/tokens"
	"github.com/sched75/sealkeeper/internal/version"
	"github.com/sched75/sealkeeper/internal/webauthn"
)

func main() {
	if len(os.Args) < 2 {
		os.Args = append(os.Args, "serve")
	}

	switch os.Args[1] {
	case "serve":
		os.Exit(runServe(os.Args[2:]))
	case "migrate":
		os.Exit(runMigrate(os.Args[2:]))
	case "backup":
		os.Exit(runBackup(os.Args[2:]))
	case "admin":
		os.Exit(runAdmin(os.Args[2:]))
	case "version", "--version", "-v":
		fmt.Println("sealkeeper", version.String(), "/", version.GoVersion())
	case "help", "--help", "-h":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown sub-command %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w *os.File) {
	fmt.Fprintf(w, `sealkeeper %s

Usage:
  sealkeeper <command> [flags]

Commands:
  serve      Run the HTTP server (default if no command given)
  migrate    Apply database migrations (forward-only)
  backup     Create or restore a backup
  admin      Manage administrator accounts (list, reset-password, enable)
  version    Print build metadata
  help       Show this message

Run "sealkeeper <command> -h" for command-specific flags.
`, version.String())
}

func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "", "override SK_HTTP_LISTEN (e.g. :8443)")
	configFile := fs.String("config", "", "override SK_CONFIG_FILE path")
	_ = fs.Parse(args)

	if *configFile != "" {
		_ = os.Setenv("SK_CONFIG_FILE", *configFile)
	}
	if *listen != "" {
		_ = os.Setenv("SK_HTTP_LISTEN", *listen)
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		return 1
	}

	logger := buildLogger(cfg)
	logger.Info("sealkeeper starting",
		"version", version.Version,
		"commit", version.Commit,
		"mode", string(cfg.Mode),
	)
	for _, w := range cfg.Warnings {
		logger.Warn("configuration: " + w)
	}

	if cfg.IsEval() {
		// FR-H.11..19 — surface the eval-mode warnings prominently.
		logger.Warn("running in evaluation mode — not for production")
		if os.Getenv("SK_MASTER_SECRET") == "" {
			logger.Warn("eval: master secret auto-generated; persist it for repeatable runs")
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	store, err := storage.Open(ctx, storage.Options{DSN: cfg.DatabaseURL})
	if err != nil {
		logger.Error("storage open failed", "err", err, "dsn", redactDSN(cfg.DatabaseURL))
		return 1
	}
	defer func() {
		if cerr := store.Close(); cerr != nil {
			logger.Warn("storage close failed", "err", cerr)
		}
	}()

	var applied []int64
	if cfg.IsEval() {
		// Eval mode runs migrations automatically so `docker run … -e SK_MODE=eval`
		// works with zero ceremony (FR-H.11..19). Production deployments are
		// expected to run `sealkeeper migrate up` as a discrete step (FR-H.63).
		if applied, err = store.MigrateUpApplied(ctx); err != nil {
			logger.Error("eval auto-migrate failed", "err", err)
			return 1
		}
	}

	srv := httpserver.New(cfg, logger)
	srv.Readiness().Add(storage.NewReadinessCheck("database", store))
	srv.SetTokens(tokens.NewRepo(store.DB()))
	auditRepo, err := openAuditRepo(ctx, cfg, store.DB(), logger, applied)
	if err != nil {
		logger.Error("audit init failed", "err", err)
		return 1
	}
	srv.SetAudit(auditRepo)
	if sender, err := buildSender(cfg, logger); err != nil {
		logger.Error("mailer setup failed", "err", err)
		return 1
	} else if sender != nil {
		srv.SetSender(sender)
	}

	// Admin console — TOTP + sessions need the master-key-derived cipher.
	box, err := cryptobox.New(cfg.MasterSecret)
	if err != nil {
		logger.Error("cryptobox init failed", "err", err)
		return 1
	}
	// FR-C.6..10: admin session lifetimes come from SK_ADMIN_SESSION_*.
	admin.SessionTTL = cfg.AdminSessionTTL
	admin.SessionIdleTTL = cfg.AdminSessionIdleTimeout
	adminRepo := admin.NewRepo(store.DB(), box).WithPasswordContext(cfg.InstanceDomain)
	if err := bootstrapAdminIfNeeded(ctx, adminRepo, logger, cfg.IsEval()); err != nil {
		logger.Error("admin bootstrap failed", "err", err)
		return 1
	}
	srv.SetAdmin(adminRepo, cfg.InstanceDomain)
	domainsRepo := domains.NewRepo(store.DB())
	elevationsRepo := elevations.NewRepo(store.DB())
	policiesRepo := policies.NewRepo(store.DB(), domainsRepo, elevationsRepo)
	srv.SetDomains(domainsRepo)
	srv.SetPolicies(policiesRepo, elevationsRepo)

	librariesRepo, err := libraries.NewRepo(store.DB(), cfg.LibrariesDir)
	if err != nil {
		logger.Error("libraries init failed", "err", err)
		return 1
	}
	srv.SetLibraries(librariesRepo)
	srv.SetMailTemplates(mailtemplates.NewRepo(store.DB()))

	integrationsRepo := integrations.NewRepo(store.DB(), box)
	// Seal integration credentials still stored in clear (pre-0015 rows).
	if n, err := integrationsRepo.SealLegacyConfigs(ctx); err != nil {
		logger.Error("sealing legacy integration configs failed", "err", err)
		return 1
	} else if n > 0 {
		logger.Info("sealed legacy integration configs", "rows", n)
	}
	dispatcher := integrations.NewDispatcher(integrationsRepo, logger, 256, 10*time.Second).
		WithNetPolicy(integrations.NetPolicy{AllowPrivate: cfg.IntegrationsAllowPrivate})
	dispatcher.Start(ctx)
	defer dispatcher.Stop()
	srv.SetIntegrations(integrationsRepo, dispatcher)
	srv.SetBranding(branding.NewRepo(store.DB()))

	// Admin-managed SMTP override. When the row carries a host we
	// rebuild the active sender right after wiring so the next reveal
	// mail uses the DB-stored relay instead of the env-wired one.
	smtpRepo := smtpconfig.NewRepo(store.DB(), box)
	srv.SetSMTPConfig(smtpRepo)
	if err := srv.RebuildSMTPSender(ctx); err != nil {
		logger.Warn("SMTP override invalid at boot — falling back to env sender", "err", err)
	}

	// WebAuthn enrollment. We derive RPID from BaseURL so a single
	// SK_BASE_URL knob configures both the public links and the
	// relying-party identity. When derivation fails (no host, IP-only
	// origin) we log and keep going — the rest of the admin surface
	// still works, /admin/security just returns 503 until the operator
	// fixes the base URL.
	if waRepo, err := newWebauthnRepo(cfg, store.DB()); err != nil {
		logger.Warn("webauthn disabled", "err", err)
	} else {
		srv.SetWebauthn(waRepo)
	}

	// FR-H.79: a public demo periodically wipes admin-supplied state so
	// each visitor sees a clean console. The resetter respects ctx so it
	// shuts down with the rest of the binary; we don't wait on it
	// explicitly — losing one in-flight reset on shutdown is fine.
	// The boot snapshot (accounts, branding, SMTP, kv) is the known state
	// every reset restores, so it is taken before any visitor gets in.
	if cfg.IsDemo() {
		logger.Info("demo mode active — data reset every 24h")
		resetter := demo.NewResetter(store.DB(), logger, 24*time.Hour).WithMailStore(srv.MailStore())
		if err := resetter.Snapshot(ctx); err != nil {
			logger.Error("demo snapshot failed", "err", err)
			return 1
		}
		go resetter.Run(ctx)
	}

	if err := srv.Run(ctx); err != nil {
		logger.Error("http server exited with error", "err", err)
		return 1
	}
	logger.Info("sealkeeper stopped cleanly")
	return 0
}

func runMigrate(args []string) int {
	sub := "up"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	_ = fs.Parse(args)

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		return 1
	}
	logger := buildLogger(cfg)

	if cfg.DatabaseURL == "" {
		fmt.Fprintln(os.Stderr, "migrate: SK_DATABASE_URL is empty")
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	store, err := storage.Open(ctx, storage.Options{DSN: cfg.DatabaseURL})
	if err != nil {
		fmt.Fprintf(os.Stderr, "storage open failed: %v\n", err)
		return 1
	}
	defer func() { _ = store.Close() }()

	switch sub {
	case "up":
		applied, err := store.MigrateUpApplied(ctx)
		if err != nil {
			logger.Error("migrate up failed", "err", err)
			return 1
		}
		// Seal the audit head anchor right after migration 0014 so a
		// migrated legacy log is anchored before anything else runs: only
		// the process that applied 0014 may take the legacy rows under the
		// key (see audit.SealAnchor).
		if cfg.MasterSecret != "" {
			if _, err := openAuditRepo(ctx, cfg, store.DB(), logger, applied); err != nil {
				logger.Error("audit init failed", "err", err)
				return 1
			}
		}
		v, _ := store.SchemaVersion(ctx)
		logger.Info("migrate up complete",
			"dialect", string(store.Dialect()),
			"schema_version", v,
			"database_url", redactDSN(cfg.DatabaseURL),
		)
	case "status":
		v, err := store.SchemaVersion(ctx)
		if err != nil {
			logger.Error("migrate status failed", "err", err)
			return 1
		}
		fmt.Printf("schema_version=%d dialect=%s\n", v, store.Dialect())
	case "down":
		fmt.Fprintln(os.Stderr, "migrate down is forbidden in SealKeeper (forward-only, FR-H.61)")
		fmt.Fprintln(os.Stderr, "to roll back: restore a backup taken before the failing upgrade")
		return 2
	default:
		fmt.Fprintf(os.Stderr, "unknown migrate sub-command %q (want: up | status)\n", sub)
		return 2
	}
	return 0
}

func runBackup(args []string) int {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "backup requires a sub-command: create | restore")
		return 2
	}
	sub := args[0]
	args = args[1:]

	output := fs.String("output", "", "output path for create")
	input := fs.String("input", "", "input path for restore")
	yes := fs.Bool("yes", false, "confirm destructive restore")
	_ = fs.Parse(args)

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		return 1
	}
	logger := buildLogger(cfg)

	switch sub {
	case "create":
		if *output == "" {
			fmt.Fprintln(os.Stderr, "backup create --output <path> required")
			return 2
		}
		logger.Info("backup create — skeleton stub", "output", *output)
	case "restore":
		if *input == "" {
			fmt.Fprintln(os.Stderr, "backup restore --input <path> required")
			return 2
		}
		if !*yes {
			fmt.Fprintln(os.Stderr, "backup restore is destructive; re-run with --yes")
			return 2
		}
		logger.Info("backup restore — skeleton stub", "input", *input)
	default:
		fmt.Fprintf(os.Stderr, "unknown backup sub-command %q\n", sub)
		return 2
	}
	return 0
}

// buildSender chooses the mailer Sender from configuration.
//
// Precedence:
//  1. SK_SMTP_HOST set → SMTPSender, regardless of mode (handy for staging
//     under eval mode against a captured-only relay like Mailpit).
//  2. Eval mode without SMTP_HOST → leave the server's default
//     CaptureSender in place (returns nil here).
//  3. Production without SMTP_HOST → log a startup warning and keep the
//     NopSender that the server defaults to. Operators usually want to
//     spot this fast; the warning is loud.
func buildSender(cfg config.Config, logger *slog.Logger) (mailer.Sender, error) {
	if strings.TrimSpace(cfg.SMTPHost) == "" {
		if !cfg.IsEval() {
			logger.Warn("no SMTP relay configured — reveal mails will be silently dropped (set SK_SMTP_HOST or run in eval mode)")
		}
		return nil, nil
	}
	tlsMode := mailer.TLSAuto
	if cfg.SMTPTLS != "" {
		tlsMode = mailer.TLSMode(cfg.SMTPTLS)
	}
	smtpCfg := mailer.SMTPConfig{
		Host:               cfg.SMTPHost,
		Port:               cfg.SMTPPort,
		Username:           cfg.SMTPUsername,
		Password:           cfg.SMTPPassword,
		FromAddress:        cfg.SMTPFrom,
		TLS:                tlsMode,
		Timeout:            cfg.SMTPTimeout,
		InsecureSkipVerify: cfg.SMTPInsecureTLS,
		ServerName:         cfg.SMTPServerName,
	}
	return mailer.NewSMTPSender(smtpCfg)
}

// bootstrapAdminIfNeeded seeds admin@localhost with a fresh 20-character
// password printed at INFO level (FR-C.1/2) when the admins table is empty.
// The account ships with force_password_change + force_totp_enroll set so
// the operator can't access the console without changing both.
//
// In eval mode only, SK_BOOTSTRAP_ADMIN_PASSWORD overrides the random
// password — used by the screenshot / demo tooling that needs a
// predictable login. Outside eval mode the env var is ignored so a
// production deployment can't accidentally pin a weak password.
func bootstrapAdminIfNeeded(ctx context.Context, repo *admin.Repo, logger *slog.Logger, evalMode bool) error {
	n, err := repo.Count(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	var pwd string
	if override := os.Getenv("SK_BOOTSTRAP_ADMIN_PASSWORD"); override != "" && evalMode {
		if len(override) < 12 {
			return fmt.Errorf("SK_BOOTSTRAP_ADMIN_PASSWORD must be at least 12 chars")
		}
		pwd = override
		logger.Info("bootstrap admin password sourced from SK_BOOTSTRAP_ADMIN_PASSWORD (eval mode)")
	} else {
		pwd, err = randomPassword(20)
		if err != nil {
			return err
		}
	}
	const email = "admin@localhost"
	if _, err := repo.Create(ctx, email, pwd); err != nil {
		return err
	}
	logger.Info("================================================================")
	logger.Info("BOOTSTRAP ADMIN PASSWORD — record this NOW, it will not be reprinted",
		"email", email,
		"password", pwd,
	)
	logger.Info("Sign in at /admin/login to change the password and enrol TOTP.")
	logger.Info("================================================================")
	return nil
}

// ----- admin subcommands ----------------------------------------------------

func runAdmin(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sealkeeper admin <reset-password|enable|list>")
		return 2
	}
	switch args[0] {
	case "reset-password":
		return runAdminResetPassword(args[1:])
	case "enable":
		return runAdminEnable(args[1:])
	case "list":
		return runAdminList(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown admin subcommand %q\n", args[0])
		fmt.Fprintln(os.Stderr, "usage: sealkeeper admin <reset-password|enable|list>")
		return 2
	}
}

// openAuditRepo binds the audit log to the HKDF-derived chain key
// (FR-E.3) and seals the head anchor. applied lists the migrations this
// process just ran; a legacy log is blessed only when 0014 is among them.
// A seal failure (e.g. migrations not applied yet) is logged, not fatal:
// VerifyChain reports the chain as unanchored until it succeeds.
func openAuditRepo(ctx context.Context, cfg config.Config, db *sql.DB, logger *slog.Logger, applied []int64) (*audit.Repo, error) {
	key, err := audit.DeriveKey(cfg.MasterSecret)
	if err != nil {
		return nil, err
	}
	repo := audit.NewRepo(db, key)
	if err := repo.SealAnchor(ctx, slices.Contains(applied, audit.HeadMigration)); err != nil {
		logger.Warn("audit anchor seal failed", "err", err)
	}
	return repo, nil
}

// appendCLIAudit records a CLI action in the keyed audit chain.
func appendCLIAudit(ctx context.Context, repo *admin.Repo, event, target string, details map[string]any) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	key, err := audit.DeriveKey(cfg.MasterSecret)
	if err != nil {
		return err
	}
	_, err = audit.NewRepo(repo.DB(), key).Append(ctx, event, "cli", target, details)
	return err
}

// openAdminRepo loads config, opens the database, runs migrations and
// binds an admin.Repo with a real cryptobox. Shared by every admin
// subcommand; returns the repo + a cleanup closure.
func openAdminRepo(ctx context.Context) (*admin.Repo, func(), error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, func() {}, fmt.Errorf("config: %w", err)
	}
	store, err := storage.Open(ctx, storage.Options{DSN: cfg.DatabaseURL})
	if err != nil {
		return nil, func() {}, fmt.Errorf("storage: %w", err)
	}
	cleanup := func() { _ = store.Close() }
	applied, err := store.MigrateUpApplied(ctx)
	if err != nil {
		cleanup()
		return nil, func() {}, fmt.Errorf("migrate: %w", err)
	}
	// An admin subcommand can be the first run after an upgrade; it must
	// seal the cut-over itself, no later boot is allowed to.
	if slices.Contains(applied, audit.HeadMigration) {
		if _, err := openAuditRepo(ctx, cfg, store.DB(), buildLogger(cfg), applied); err != nil {
			cleanup()
			return nil, func() {}, fmt.Errorf("audit: %w", err)
		}
	}
	box, err := cryptobox.New(cfg.MasterSecret)
	if err != nil {
		cleanup()
		return nil, func() {}, fmt.Errorf("cryptobox: %w", err)
	}
	return admin.NewRepo(store.DB(), box).WithPasswordContext(cfg.InstanceDomain), cleanup, nil
}

func runAdminResetPassword(args []string) int {
	fs := flag.NewFlagSet("admin reset-password", flag.ExitOnError)
	email := fs.String("email", "", "email of the admin to reset (required)")
	customPwd := fs.String("password", "", "use this password instead of generating one (must clear ANSSI B3)")
	_ = fs.Parse(args)
	if *email == "" {
		fmt.Fprintln(os.Stderr, "--email is required")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repo, cleanup, err := openAdminRepo(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "admin reset-password: %v\n", err)
		return 1
	}
	defer cleanup()

	a, err := repo.FindByEmail(ctx, *email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "admin reset-password: %v\n", err)
		return 1
	}

	pwd := *customPwd
	if pwd == "" {
		pwd, err = randomPassword(20)
		if err != nil {
			fmt.Fprintf(os.Stderr, "admin reset-password: rng: %v\n", err)
			return 1
		}
	}
	if err := repo.ResetForBootstrap(ctx, a.ID, pwd); err != nil {
		fmt.Fprintf(os.Stderr, "admin reset-password: %v\n", err)
		return 1
	}
	fmt.Println("================================================================")
	fmt.Println("ADMIN PASSWORD RESET — record this NOW, it will not be reprinted")
	fmt.Println("  email:    ", a.Email)
	fmt.Println("  password: ", pwd)
	fmt.Println("================================================================")
	fmt.Println("Next sign-in will force a password change + fresh TOTP enrolment.")
	fmt.Println("Existing sessions of this admin have been revoked.")
	if a.Disabled {
		fmt.Println("This account is disabled: run 'sealkeeper admin enable --email " + a.Email + "' to sign in.")
	}
	return 0
}

// runAdminEnable clears disabled_at on one admin. It is the way back when
// no active admin is left to re-enable anyone from the console.
func runAdminEnable(args []string) int {
	fs := flag.NewFlagSet("admin enable", flag.ExitOnError)
	email := fs.String("email", "", "email of the admin to re-enable (required)")
	_ = fs.Parse(args)
	if *email == "" {
		fmt.Fprintln(os.Stderr, "--email is required")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repo, cleanup, err := openAdminRepo(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "admin enable: %v\n", err)
		return 1
	}
	defer cleanup()

	a, err := repo.FindByEmail(ctx, *email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "admin enable: %v\n", err)
		return 1
	}
	if !a.Disabled {
		fmt.Printf("%s is already active\n", a.Email)
		return 0
	}
	if err := repo.SetDisabled(ctx, a.ID, false); err != nil {
		fmt.Fprintf(os.Stderr, "admin enable: %v\n", err)
		return 1
	}
	// The audit chain is HMAC-keyed from the master secret: derive the same
	// key the server uses, or the row would break the chain.
	if err := appendCLIAudit(ctx, repo, "admin.enabled", a.Email,
		map[string]any{"admin_id": a.ID, "via": "cli"}); err != nil {
		fmt.Fprintf(os.Stderr, "admin enable: audit append failed: %v\n", err)
	}
	fmt.Printf("%s re-enabled\n", a.Email)
	return 0
}

func runAdminList(args []string) int {
	fs := flag.NewFlagSet("admin list", flag.ExitOnError)
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repo, cleanup, err := openAdminRepo(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "admin list: %v\n", err)
		return 1
	}
	defer cleanup()

	rows, err := repo.List(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "admin list: %v\n", err)
		return 1
	}
	if len(rows) == 0 {
		fmt.Println("(no admin accounts)")
		return 0
	}
	fmt.Printf("%-4s %-32s %-10s %-20s\n", "id", "email", "status", "last login")
	for _, a := range rows {
		status := "active"
		if a.Disabled {
			status = "disabled"
		} else if a.ForceTOTPEnroll {
			status = "pending"
		}
		last := "—"
		if a.LastLoginAt != nil {
			last = a.LastLoginAt.UTC().Format("2006-01-02 15:04")
		}
		fmt.Printf("%-4d %-32s %-10s %-20s\n", a.ID, a.Email, status, last)
	}
	return 0
}

// randomPassword draws n characters uniformly from a 66-glyph alphabet
// and redraws until the result clears admin.ValidateAdminPassword, so a
// generated password always satisfies the operator policy (a draw can
// miss a character class, or happen to spell a pattern).
func randomPassword(n int) (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%&*+=?"
	// Bytes at or above limit are rejected so every glyph is equally likely.
	const limit = 256 - 256%len(alphabet)
	for attempt := 0; attempt < 100; attempt++ {
		out := make([]byte, 0, n)
		buf := make([]byte, n)
		for len(out) < n {
			if _, err := rand.Read(buf); err != nil {
				return "", err
			}
			for _, x := range buf {
				if int(x) < limit && len(out) < n {
					out = append(out, alphabet[int(x)%len(alphabet)])
				}
			}
		}
		if admin.ValidateAdminPassword(string(out)) == nil {
			return string(out), nil
		}
	}
	return "", errors.New("randomPassword: no draw cleared the password policy")
}

func buildLogger(cfg config.Config) *slog.Logger {
	var lvl slog.Level
	switch cfg.LogLevel {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if cfg.LogFormat == "text" {
		return slog.New(slog.NewTextHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}

// redactDSN strips the password from a libpq-style URL for log output.
func redactDSN(dsn string) string {
	if dsn == "" {
		return ""
	}
	// crude redaction good enough for log lines; keeps scheme and host visible.
	if at := indexOfRune(dsn, '@'); at > 0 {
		if scheme := indexOf(dsn, "://"); scheme > 0 {
			return dsn[:scheme+3] + "***" + dsn[at:]
		}
	}
	return dsn
}

func indexOfRune(s string, r rune) int {
	for i, c := range s {
		if c == r {
			return i
		}
	}
	return -1
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// newWebauthnRepo wires the WebAuthn relying party. RPID is the bare host
// of cfg.BaseURL (no scheme, no port — that's what the spec mandates) and
// the origin is BaseURL stripped of any trailing slash.
func newWebauthnRepo(cfg config.Config, db *sql.DB) (*webauthn.Repo, error) {
	host := cfg.InstanceDomain
	if host == "" {
		return nil, fmt.Errorf("instance domain unresolved")
	}
	origin := strings.TrimRight(cfg.BaseURL, "/")
	if origin == "" {
		return nil, fmt.Errorf("base URL unresolved")
	}
	return webauthn.NewRepo(db, webauthn.Config{
		RPID:          host,
		RPDisplayName: "SealKeeper — " + host,
		Origins:       []string{origin},
	})
}
