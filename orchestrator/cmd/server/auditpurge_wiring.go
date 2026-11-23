package main

import (
	"context"
	"log"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/config"
	"github.com/audspect/bas/internal/auditarchive"
	"github.com/audspect/bas/internal/auditpurge"
	"github.com/audspect/bas/internal/db"
)

// startAuditPurge starts the audit-log purge when it is enabled. Purging stays off unless every setting is present,
// the keys load, and the public key matches the private key. Each missing piece is logged by name.
func startAuditPurge(ctx context.Context, cfg *config.Config, adminPool, appPool *pgxpool.Pool) {
	if !cfg.AuditPurgeEnabled {
		log.Printf("[auditpurge] disabled (AUDIT_PURGE_ENABLED is not true)")
		return
	}
	var missing []string
	if cfg.AuditPurgePassword == "" {
		missing = append(missing, "AUDIT_PURGE_PASSWORD")
	}
	if cfg.AuditArchiveDir == "" {
		missing = append(missing, "AUDIT_ARCHIVE_DIR")
	}
	if cfg.AuditArchivePrivateKey == "" {
		missing = append(missing, "AUDIT_ARCHIVE_PRIVATE_KEY")
	}
	if cfg.AuditArchivePublicKey == "" {
		missing = append(missing, "AUDIT_ARCHIVE_PUBLIC_KEY")
	}
	if len(missing) > 0 {
		log.Printf("[auditpurge] disabled: not configured: %s", strings.Join(missing, ", "))
		return
	}
	priv, err := auditarchive.LoadPrivateKey(cfg.AuditArchivePrivateKey)
	if err != nil {
		log.Printf("[auditpurge] disabled: %v", err)
		return
	}
	pub, err := auditarchive.LoadPublicKey(cfg.AuditArchivePublicKey)
	if err != nil {
		log.Printf("[auditpurge] disabled: %v", err)
		return
	}
	if !priv.PublicKey.Equal(pub) {
		log.Printf("[auditpurge] disabled: AUDIT_ARCHIVE_PUBLIC_KEY does not match AUDIT_ARCHIVE_PRIVATE_KEY")
		return
	}
	if err := db.EnsurePurgeRole(ctx, adminPool, cfg.AuditPurgePassword); err != nil {
		log.Printf("[auditpurge] disabled: %v", err)
		return
	}
	pcfg := appPool.Config().Copy()
	pcfg.ConnConfig.User = "bas_audit_purger"
	pcfg.ConnConfig.Password = cfg.AuditPurgePassword
	purgePool, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		log.Printf("[auditpurge] disabled: purge pool: %v", err)
		return
	}
	days := cfg.AuditPurgeMaxDays
	if days == 0 {
		days = 365
	}
	auditpurge.StartDaily(ctx, purgePool, auditpurge.Config{
		Enabled: true, MaxRetentionDays: days, BatchSize: 500, ArchiveDir: cfg.AuditArchiveDir,
	}, priv, auditpurge.AuditRecorder{Pool: appPool})
	log.Printf("[auditpurge] enabled: rows older than %d days are archived, verified, then deleted daily", days)
}
