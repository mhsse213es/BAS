package db

import (
	"errors"
	"fmt"
	"net/url"
)

// ErrInsecureDBTLS is returned when a DSN does not verify the database server
// certificate and hostname.
var ErrInsecureDBTLS = errors.New("database connection must use sslmode=verify-full with sslrootcert")

// RequireVerifiedDBTLS refuses any DSN that does not verify the server's
// certificate chain and hostname. Only verify-full does both: require and
// verify-ca skip the hostname check, and prefer falls back to plaintext.
//
// devOK is the explicit development override (BAS_DB_TLS_DEV_INSECURE=1). It
// is never set by the installer or the compose file.
func RequireVerifiedDBTLS(dsn string, devOK bool) error {
	if dsn == "" {
		return errors.New("database URL is empty")
	}
	if devOK {
		return nil
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return fmt.Errorf("database URL does not parse: %w", err)
	}
	q := u.Query()
	if q.Get("sslmode") != "verify-full" {
		return fmt.Errorf("%w: sslmode is %q", ErrInsecureDBTLS, q.Get("sslmode"))
	}
	if q.Get("sslrootcert") == "" {
		return fmt.Errorf("%w: sslrootcert is not set", ErrInsecureDBTLS)
	}
	return nil
}
