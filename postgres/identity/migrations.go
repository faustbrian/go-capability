package identitycapability

import (
	"embed"
	"io/fs"
)

//go:embed migrations/*.sql
var files embed.FS

// Migrations returns additive forward-only migrations rooted at filenames. Use
// a separate migration ledger from the legacy consumption store. No legacy row
// is imported, reset or removed. Downgrade is unsupported because deleting
// retained one-time state permits replay. Application roles must not own tables
// or have DDL, TRUNCATE, DELETE or trigger-disable privileges. Issuance and
// retirement must use owned phases, never client-controlled inserts. The native
// Issuer owns original inserts; retention/revocation phases remain unfinished.
func Migrations() fs.FS { source, _ := fs.Sub(files, "migrations"); return source }
