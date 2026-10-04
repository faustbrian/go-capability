package postgres

import (
	"context"
	"database/sql"
	"unicode/utf8"

	"github.com/faustbrian/go-capability"
)

// MigrateLegacyConsumption upgrades migration 001 to the issuer-scoped schema
// version 2, preserving every use count, maximum and expiry. legacyIssuer must
// be the owner-proven single issuer of all existing rows, never a token claim.
// The caller must fence and drain all old writers first and supply an open
// transaction. This function locks the table but does not commit or roll back;
// on failure the caller must roll back. Commit before activating new writers.
// An already upgraded schema is not migrated again. Unknown legacy ownership
// requires retiring old grants beyond expiry plus verification skew instead.
func MigrateLegacyConsumption(ctx context.Context, tx *sql.Tx, legacyIssuer string) error {
	if ctx == nil || tx == nil || legacyIssuer == "" || len(legacyIssuer) > 256 || !utf8.ValidString(legacyIssuer) {
		return capability.ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `LOCK TABLE capability_consumptions IN ACCESS EXCLUSIVE MODE`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE capability_consumptions ADD COLUMN issuer text`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE capability_consumptions SET issuer = $1`, legacyIssuer); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE capability_consumptions ALTER COLUMN issuer SET NOT NULL`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE capability_consumptions ADD CONSTRAINT capability_consumptions_issuer_check CHECK (issuer <> '' AND octet_length(issuer) <= 256)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE capability_consumptions DROP CONSTRAINT capability_consumptions_pkey`); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `ALTER TABLE capability_consumptions ADD PRIMARY KEY (issuer, capability_id)`)
	return err
}
