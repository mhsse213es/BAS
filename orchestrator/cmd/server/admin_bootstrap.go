package main

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
)

// minAdminPasswordLen matches the installer and the first-run setup endpoint.
const minAdminPasswordLen = 10

// adminAction is what startup does about the primary admin account.
type adminAction int

const (
	// adminLeave: an admin exists. Startup never changes it, so a password changed in the dashboard
	// survives restarts.
	adminLeave adminAction = iota
	// adminCreate: no admin exists and an operator supplied a password. Create the first admin.
	adminCreate
	// adminNone: no admin exists and no password was supplied. No credential is created. The first
	// admin is made through the first-run setup endpoint, never with a built-in default.
	adminNone
)

// decideAdminBootstrap is the whole policy, kept free of I/O so it can be tested directly.
func decideAdminBootstrap(adminExists bool, password string) (adminAction, error) {
	if adminExists {
		return adminLeave, nil
	}
	if password == "" {
		return adminNone, nil
	}
	if len(password) < minAdminPasswordLen {
		return adminNone, fmt.Errorf("admin password must be at least %d characters", minAdminPasswordLen)
	}
	return adminCreate, nil
}

// ensureAdminUser runs at startup. It creates the first admin from the environment when none exists.
// It never overwrites an existing admin, and it never creates an account with a built-in password.
func ensureAdminUser(pool *pgxpool.Pool, adminUsername, adminPassword string) error {
	if adminUsername == "" {
		adminUsername = "admin"
	}
	ctx := context.Background()
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE role = 'admin')`).Scan(&exists); err != nil {
		return fmt.Errorf("check admin: %w", err)
	}
	act, err := decideAdminBootstrap(exists, adminPassword)
	if err != nil {
		return err
	}
	switch act {
	case adminLeave:
		return nil
	case adminNone:
		log.Printf("[!] No admin account and no BAS_ADMIN_PASSWORD set. Create the first admin through the setup endpoint.")
		return nil
	}
	hash, err := auth.HashPassword(adminPassword)
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}
	// Insert only if still no admin. The guard is in the statement, so two starts cannot both create one.
	tag, err := pool.Exec(ctx, `
		INSERT INTO users (username, password_hash, role, is_active, must_change_pw)
		SELECT $1, $2, 'admin', true, false
		WHERE NOT EXISTS (SELECT 1 FROM users WHERE role = 'admin')`, adminUsername, hash)
	if err != nil {
		return fmt.Errorf("create admin: %w", err)
	}
	if tag.RowsAffected() == 1 {
		log.Printf("[+] Initial admin created from BAS_ADMIN_PASSWORD (username: %s)", adminUsername)
	}
	return nil
}
