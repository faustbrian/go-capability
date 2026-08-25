// Package postgres provides durable atomic capability consumption through
// database/sql and PostgreSQL row locks. The caller supplies the SQL driver.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-capability"
)

const maxInsertRetries = 3

type storedConsumption struct {
	uses      uint32
	maxUses   uint32
	expiresAt time.Time
	expired   bool
}

type beginner interface {
	begin(context.Context) (transaction, error)
}

type transaction interface {
	load(context.Context, string) (storedConsumption, bool, error)
	insert(context.Context, capability.Consumption) (bool, error)
	replace(context.Context, capability.Consumption, uint32) error
	cleanup(context.Context, time.Time) (int64, error)
	Commit() error
	Rollback() error
}

// ConsumptionStore owns durable PostgreSQL transactions for replay state.
type ConsumptionStore struct{ database beginner }

// NewConsumptionStore binds store to db. The schema in migrations must be
// installed before use. db remains caller-owned and is never closed here.
func NewConsumptionStore(db *sql.DB) (*ConsumptionStore, error) {
	if db == nil {
		return nil, capability.ErrInvalidConfiguration
	}
	return newStore(sqlBeginner{database: db}), nil
}

func newStore(database beginner) *ConsumptionStore {
	return &ConsumptionStore{database: database}
}

// Consume serializes one capability row, then commits an increment only when
// the signed identity and use bound match. Commit errors have unknown outcome.
func (store *ConsumptionStore) Consume(ctx context.Context, request capability.Consumption) (capability.ConsumptionResult, error) {
	if err := validateRequest(ctx, request); err != nil {
		return capability.ConsumptionResult{}, err
	}
	for range maxInsertRetries {
		result, retry, err := store.consumeOnce(ctx, request)
		if err != nil || !retry {
			return result, err
		}
	}
	return capability.ConsumptionResult{}, capability.ErrReplayConflict
}

func (store *ConsumptionStore) consumeOnce(ctx context.Context, request capability.Consumption) (capability.ConsumptionResult, bool, error) {
	// PostgreSQL timestamps have microsecond precision. Normalize every attempt
	// before persistence and replay comparison so reloaded state keeps its identity.
	request.ExpiresAt = request.ExpiresAt.Truncate(time.Microsecond)
	tx, err := store.database.begin(ctx)
	if err == nil {
		defer func() { _ = tx.Rollback() }()
	}
	if err != nil {
		return capability.ConsumptionResult{}, false, err
	}
	record, found, err := tx.load(ctx, request.CapabilityID)
	if err != nil {
		_ = tx.Rollback()
		return capability.ConsumptionResult{}, false, err
	}
	switch found {
	case false:
		inserted, insertErr := tx.insert(ctx, request)
		if insertErr != nil {
			_ = tx.Rollback()
			return capability.ConsumptionResult{}, false, insertErr
		}
		if !inserted {
			_ = tx.Rollback()
			return capability.ConsumptionResult{}, true, nil
		}
		if err := tx.Commit(); err != nil {
			return capability.ConsumptionResult{}, false, err
		}
		return capability.ConsumptionResult{Use: 1, Remaining: request.MaxUses - 1}, false, nil
	}
	if record.expired {
		if err := tx.replace(ctx, request, 1); err != nil {
			_ = tx.Rollback()
			return capability.ConsumptionResult{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return capability.ConsumptionResult{}, false, err
		}
		return capability.ConsumptionResult{Use: 1, Remaining: request.MaxUses - 1}, false, nil
	}
	if record.maxUses != request.MaxUses ||
		!record.expiresAt.Truncate(time.Microsecond).Equal(request.ExpiresAt) {
		_ = tx.Rollback()
		return capability.ConsumptionResult{}, false, capability.ErrReplayConflict
	}
	if record.uses >= record.maxUses {
		_ = tx.Rollback()
		return capability.ConsumptionResult{}, false, capability.ErrReplayExhausted
	}
	uses := record.uses + 1
	if err := tx.replace(ctx, request, uses); err != nil {
		_ = tx.Rollback()
		return capability.ConsumptionResult{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return capability.ConsumptionResult{}, false, err
	}
	return capability.ConsumptionResult{Use: uses, Remaining: request.MaxUses - uses}, false, nil
}

// Cleanup deletes state whose expiry is at or before cutoff.
func (store *ConsumptionStore) Cleanup(ctx context.Context, cutoff time.Time) (int64, error) {
	if ctx == nil || cutoff.IsZero() {
		return 0, capability.ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	tx, err := store.database.begin(ctx)
	if err != nil {
		return 0, err
	}
	removed, err := tx.cleanup(ctx, cutoff)
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return removed, nil
}

func validateRequest(ctx context.Context, request capability.Consumption) error {
	if ctx == nil || request.CapabilityID == "" || len(request.CapabilityID) > 256 ||
		!utf8.ValidString(request.CapabilityID) || request.MaxUses == 0 || request.ExpiresAt.IsZero() {
		return capability.ErrInvalidConfiguration
	}
	return ctx.Err()
}

type sqlBeginner struct{ database *sql.DB }

func (database sqlBeginner) begin(ctx context.Context) (transaction, error) {
	tx, err := database.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, err
	}
	return sqlTransaction{transaction: tx}, nil
}

type sqlTransaction struct{ transaction *sql.Tx }

func (tx sqlTransaction) load(ctx context.Context, capabilityID string) (storedConsumption, bool, error) {
	var record storedConsumption
	err := tx.transaction.QueryRowContext(ctx, `
SELECT uses, max_uses, expires_at, expires_at <= CURRENT_TIMESTAMP
FROM capability_consumptions
WHERE capability_id = $1
FOR UPDATE`, capabilityID).Scan(&record.uses, &record.maxUses, &record.expiresAt, &record.expired)
	if errors.Is(err, sql.ErrNoRows) {
		return storedConsumption{}, false, nil
	}
	return record, err == nil, err
}

func (tx sqlTransaction) insert(ctx context.Context, request capability.Consumption) (bool, error) {
	result, err := tx.transaction.ExecContext(ctx, `
INSERT INTO capability_consumptions (capability_id, uses, max_uses, expires_at)
VALUES ($1, 1, $2, $3)
ON CONFLICT (capability_id) DO NOTHING`, request.CapabilityID, request.MaxUses, request.ExpiresAt)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

func (tx sqlTransaction) replace(ctx context.Context, request capability.Consumption, uses uint32) error {
	_, err := tx.transaction.ExecContext(ctx, `
UPDATE capability_consumptions
SET uses = $2, max_uses = $3, expires_at = $4
WHERE capability_id = $1`, request.CapabilityID, uses, request.MaxUses, request.ExpiresAt)
	return err
}

func (tx sqlTransaction) cleanup(ctx context.Context, cutoff time.Time) (int64, error) {
	result, err := tx.transaction.ExecContext(ctx, `
DELETE FROM capability_consumptions
WHERE expires_at <= $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (tx sqlTransaction) Commit() error   { return tx.transaction.Commit() }
func (tx sqlTransaction) Rollback() error { return tx.transaction.Rollback() }
