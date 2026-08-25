package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
)

var driverSequence atomic.Int64

func TestStoreSerializesConcurrentOneTimeConsumption(t *testing.T) {
	backend := newFakeBackend()
	store := newStore(backend)
	request := capability.Consumption{CapabilityID: "cap-1", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}
	const contenders = 24
	var accepted atomic.Int64
	var exhausted atomic.Int64
	var wait sync.WaitGroup
	wait.Add(contenders)
	for range contenders {
		go func() {
			defer wait.Done()
			_, err := store.Consume(context.Background(), request)
			switch {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, capability.ErrReplayExhausted):
				exhausted.Add(1)
			default:
				t.Errorf("Consume() error = %v", err)
			}
		}()
	}
	wait.Wait()
	if accepted.Load() != 1 || exhausted.Load() != contenders-1 {
		t.Fatalf("accepted = %d, exhausted = %d", accepted.Load(), exhausted.Load())
	}
}

func TestStoreReplacesExpiredStateAndRejectsIdentityConflict(t *testing.T) {
	backend := newFakeBackend()
	store := newStore(backend)
	request := capability.Consumption{CapabilityID: "cap-2", MaxUses: 2, ExpiresAt: time.Now().Add(time.Hour)}
	first, err := store.Consume(context.Background(), request)
	if err != nil || first.Use != 1 || first.Remaining != 1 {
		t.Fatalf("Consume() = %#v, %v", first, err)
	}
	conflict := request
	conflict.MaxUses = 3
	if _, err := store.Consume(context.Background(), conflict); !errors.Is(err, capability.ErrReplayConflict) {
		t.Fatalf("Consume(conflict) error = %v", err)
	}
	backend.expire("cap-2")
	replacement := request
	replacement.ExpiresAt = time.Now().Add(2 * time.Hour)
	result, err := store.Consume(context.Background(), replacement)
	if err != nil || result.Use != 1 || result.Remaining != 1 {
		t.Fatalf("Consume(replacement) = %#v, %v", result, err)
	}
}

func TestStorePropagatesCommitAndCancellationFailures(t *testing.T) {
	backend := newFakeBackend()
	backend.commitErr = errors.New("commit result unknown")
	store := newStore(backend)
	request := capability.Consumption{CapabilityID: "cap-3", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}
	if _, err := store.Consume(context.Background(), request); !errors.Is(err, backend.commitErr) {
		t.Fatalf("Consume(commit failure) error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Consume(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("Consume(canceled) error = %v", err)
	}
}

func TestStorePropagatesTransactionFailuresAndRetriesInsertRaces(t *testing.T) {
	request := capability.Consumption{
		CapabilityID: "cap-fault",
		MaxUses:      2,
		ExpiresAt:    time.Unix(2_000_000_000, 123_456_789).UTC(),
	}
	backend := newFakeBackend()
	backend.beginErr = errors.New("begin")
	if _, err := newStore(backend).Consume(context.Background(), request); !errors.Is(err, backend.beginErr) {
		t.Fatalf("Consume(begin) error = %v", err)
	}
	backend = newFakeBackend()
	backend.loadErr = errors.New("load")
	if _, err := newStore(backend).Consume(context.Background(), request); !errors.Is(err, backend.loadErr) {
		t.Fatalf("Consume(load) error = %v", err)
	}
	backend = newFakeBackend()
	backend.insertErr = errors.New("insert")
	if _, err := newStore(backend).Consume(context.Background(), request); !errors.Is(err, backend.insertErr) {
		t.Fatalf("Consume(insert) error = %v", err)
	}
	backend = newFakeBackend()
	backend.insertConflicts = maxInsertRetries
	if _, err := newStore(backend).Consume(context.Background(), request); !errors.Is(err, capability.ErrReplayConflict) {
		t.Fatalf("Consume(insert races) error = %v", err)
	}
	backend = newFakeBackend()
	backend.insertConflicts = 1
	result, err := newStore(backend).Consume(context.Background(), request)
	if err != nil || result.Use != 1 {
		t.Fatalf("Consume(insert retry success) = %#v, %v", result, err)
	}
	backend = newFakeBackend()
	backend.replaceErr = errors.New("replace")
	backend.records[request.CapabilityID] = fakeRecord{uses: 1, maxUses: 2, expiresAt: request.ExpiresAt}
	if _, err := newStore(backend).Consume(context.Background(), request); !errors.Is(err, backend.replaceErr) {
		t.Fatalf("Consume(replace) error = %v", err)
	}
	backend = newFakeBackend()
	backend.replaceErr = errors.New("replace expired")
	backend.records[request.CapabilityID] = fakeRecord{uses: 1, maxUses: 2, expiresAt: request.ExpiresAt, expired: true}
	if _, err := newStore(backend).Consume(context.Background(), request); !errors.Is(err, backend.replaceErr) {
		t.Fatalf("Consume(replace expired) error = %v", err)
	}
	backend = newFakeBackend()
	backend.records[request.CapabilityID] = fakeRecord{uses: 1, maxUses: 2, expiresAt: request.ExpiresAt}
	result, err = newStore(backend).Consume(context.Background(), request)
	if err != nil || result.Use != 2 || result.Remaining != 0 {
		t.Fatalf("Consume(increment) = %#v, %v", result, err)
	}
	backend = newFakeBackend()
	backend.commitErr = errors.New("increment commit")
	backend.records[request.CapabilityID] = fakeRecord{uses: 1, maxUses: 2, expiresAt: request.ExpiresAt}
	if _, err := newStore(backend).Consume(context.Background(), request); !errors.Is(err, backend.commitErr) {
		t.Fatalf("Consume(increment commit) error = %v", err)
	}
	backend = newFakeBackend()
	backend.commitErr = errors.New("expired commit")
	backend.records[request.CapabilityID] = fakeRecord{uses: 1, maxUses: 2, expiresAt: request.ExpiresAt, expired: true}
	if _, err := newStore(backend).Consume(context.Background(), request); !errors.Is(err, backend.commitErr) {
		t.Fatalf("Consume(expired commit) error = %v", err)
	}
}

func TestStoreCleanupValidationAndFailures(t *testing.T) {
	backend := newFakeBackend()
	store := newStore(backend)
	cutoff := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var nilContext context.Context
	if _, err := store.Cleanup(nilContext, cutoff); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("Cleanup(nil) error = %v", err)
	}
	if _, err := store.Cleanup(context.Background(), time.Time{}); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("Cleanup(zero) error = %v", err)
	}
	if _, err := store.Cleanup(ctx, cutoff); !errors.Is(err, context.Canceled) {
		t.Fatalf("Cleanup(canceled) error = %v", err)
	}
	backend.beginErr = errors.New("begin")
	if _, err := store.Cleanup(context.Background(), cutoff); !errors.Is(err, backend.beginErr) {
		t.Fatalf("Cleanup(begin) error = %v", err)
	}
	backend.beginErr = nil
	backend.cleanupErr = errors.New("cleanup")
	if _, err := store.Cleanup(context.Background(), cutoff); !errors.Is(err, backend.cleanupErr) {
		t.Fatalf("Cleanup(delete) error = %v", err)
	}
	backend.cleanupErr = nil
	backend.cleanupRows = 3
	removed, err := store.Cleanup(context.Background(), cutoff)
	if err != nil || removed != 3 {
		t.Fatalf("Cleanup() = %d, %v", removed, err)
	}
	backend.commitErr = errors.New("commit")
	if _, err := store.Cleanup(context.Background(), cutoff); !errors.Is(err, backend.commitErr) {
		t.Fatalf("Cleanup(commit) error = %v", err)
	}
}

func TestStoreValidatesConstructorAndConsumption(t *testing.T) {
	if _, err := NewConsumptionStore(nil); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("NewConsumptionStore(nil) error = %v", err)
	}
	store := newStore(newFakeBackend())
	valid := capability.Consumption{CapabilityID: "cap", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}
	for name, request := range map[string]capability.Consumption{
		"empty ID":      {MaxUses: 1, ExpiresAt: valid.ExpiresAt},
		"long ID":       {CapabilityID: string(make([]byte, 257)), MaxUses: 1, ExpiresAt: valid.ExpiresAt},
		"invalid UTF-8": {CapabilityID: string([]byte{0xff}), MaxUses: 1, ExpiresAt: valid.ExpiresAt},
		"zero uses":     {CapabilityID: "cap", ExpiresAt: valid.ExpiresAt},
		"zero expiry":   {CapabilityID: "cap", MaxUses: 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := store.Consume(context.Background(), request); !errors.Is(err, capability.ErrInvalidConfiguration) {
				t.Fatalf("Consume() error = %v", err)
			}
		})
	}
	var nilContext context.Context
	if _, err := store.Consume(nilContext, valid); !errors.Is(err, capability.ErrInvalidConfiguration) {
		t.Fatalf("Consume(nil context) error = %v", err)
	}
	exactBoundary := valid
	exactBoundary.CapabilityID = string(make([]byte, 256))
	if result, err := store.Consume(context.Background(), exactBoundary); err != nil || result.Use != 1 {
		t.Fatalf("Consume(256-byte ID) = %#v, %v", result, err)
	}
}

func TestConsumeOnceDistinguishesMissingAndExistingRows(t *testing.T) {
	request := capability.Consumption{
		CapabilityID: "missing",
		MaxUses:      2,
		ExpiresAt:    time.Unix(2_000_000_000, 987_654_321).UTC(),
	}
	backend := newFakeBackend()
	result, retry, err := newStore(backend).consumeOnce(context.Background(), request)
	if err != nil || retry || result.Use != 1 || result.Remaining != 1 {
		t.Fatalf("consumeOnce(missing) = %#v, %t, %v", result, retry, err)
	}

	request.CapabilityID = "existing"
	backend.records[request.CapabilityID] = fakeRecord{uses: 1, maxUses: 2, expiresAt: request.ExpiresAt}
	result, retry, err = newStore(backend).consumeOnce(context.Background(), request)
	if err != nil || retry || result.Use != 2 || result.Remaining != 0 {
		t.Fatalf("consumeOnce(existing) = %#v, %t, %v", result, retry, err)
	}
}

func TestConsumeNormalizesExpiryToPostgreSQLPrecision(t *testing.T) {
	request := capability.Consumption{
		CapabilityID: "postgres-precision",
		MaxUses:      2,
		ExpiresAt:    time.Unix(1_700_000_000, 123_456_789).UTC(),
	}
	backend := newFakeBackend()
	backend.records[request.CapabilityID] = fakeRecord{
		uses:      1,
		maxUses:   request.MaxUses,
		expiresAt: request.ExpiresAt.Truncate(time.Microsecond),
	}

	result, err := newStore(backend).Consume(context.Background(), request)
	if err != nil || result.Use != 2 || result.Remaining != 0 {
		t.Fatalf("Consume() = %#v, %v", result, err)
	}
	if stored := backend.records[request.CapabilityID].expiresAt; !stored.Equal(request.ExpiresAt.Truncate(time.Microsecond)) {
		t.Fatalf("stored expiry = %v", stored)
	}
}

func TestDatabaseSQLAdapterExecutesRowsResultsAndTransactions(t *testing.T) {
	state := &stubSQLState{queryValues: []driver.Value{int64(1), int64(2), time.Now(), false}, execRows: 1}
	database := openStubDatabase(t, state)
	store, err := NewConsumptionStore(database)
	if err != nil || store == nil {
		t.Fatalf("NewConsumptionStore() = %#v, %v", store, err)
	}
	beginner := sqlBeginner{database: database}
	tx, err := beginner.begin(context.Background())
	if err != nil {
		t.Fatalf("begin() error = %v", err)
	}
	record, found, err := tx.load(context.Background(), "cap")
	if err != nil || !found || record.uses != 1 || record.maxUses != 2 || record.expired {
		t.Fatalf("load() = %#v, %t, %v", record, found, err)
	}
	request := capability.Consumption{CapabilityID: "cap", MaxUses: 2, ExpiresAt: record.expiresAt}
	inserted, err := tx.insert(context.Background(), request)
	if err != nil || !inserted {
		t.Fatalf("insert() = %t, %v", inserted, err)
	}
	if err := tx.replace(context.Background(), request, 2); err != nil {
		t.Fatalf("replace() error = %v", err)
	}
	removed, err := tx.cleanup(context.Background(), time.Now())
	if err != nil || removed != 1 {
		t.Fatalf("cleanup() = %d, %v", removed, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	state.queryValues = nil
	tx, _ = beginner.begin(context.Background())
	if _, found, err := tx.load(context.Background(), "missing"); err != nil || found {
		t.Fatalf("load(missing) found = %t, error = %v", found, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
}

func TestDatabaseSQLAdapterPropagatesDriverFailures(t *testing.T) {
	state := &stubSQLState{}
	database := openStubDatabase(t, state)
	beginner := sqlBeginner{database: database}
	state.beginErr = errors.New("begin")
	if _, err := beginner.begin(context.Background()); !errors.Is(err, state.beginErr) {
		t.Fatalf("begin() error = %v", err)
	}
	state.beginErr = nil

	state.queryErr = errors.New("query")
	tx, _ := beginner.begin(context.Background())
	if _, _, err := tx.load(context.Background(), "cap"); !errors.Is(err, state.queryErr) {
		t.Fatalf("load() error = %v", err)
	}
	_ = tx.Rollback()
	state.queryErr = nil

	request := capability.Consumption{CapabilityID: "cap", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}
	state.execErr = errors.New("exec")
	tx, _ = beginner.begin(context.Background())
	if _, err := tx.insert(context.Background(), request); !errors.Is(err, state.execErr) {
		t.Fatalf("insert() error = %v", err)
	}
	if err := tx.replace(context.Background(), request, 1); !errors.Is(err, state.execErr) {
		t.Fatalf("replace() error = %v", err)
	}
	if _, err := tx.cleanup(context.Background(), time.Now()); !errors.Is(err, state.execErr) {
		t.Fatalf("cleanup() error = %v", err)
	}
	_ = tx.Rollback()
	state.execErr = nil
	state.rowsErr = errors.New("rows affected")
	tx, _ = beginner.begin(context.Background())
	if _, err := tx.insert(context.Background(), request); !errors.Is(err, state.rowsErr) {
		t.Fatalf("insert(rows) error = %v", err)
	}
	if _, err := tx.cleanup(context.Background(), time.Now()); !errors.Is(err, state.rowsErr) {
		t.Fatalf("cleanup(rows) error = %v", err)
	}
	_ = tx.Rollback()
	state.rowsErr = nil
	state.commitErr = errors.New("commit")
	tx, _ = beginner.begin(context.Background())
	if err := tx.Commit(); !errors.Is(err, state.commitErr) {
		t.Fatalf("Commit() error = %v", err)
	}
}

func openStubDatabase(t *testing.T, state *stubSQLState) *sql.DB {
	t.Helper()
	name := fmt.Sprintf("capability-postgres-%d", driverSequence.Add(1))
	sql.Register(name, stubSQLDriver{state: state})
	database, err := sql.Open(name, "")
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

type stubSQLState struct {
	mu          sync.Mutex
	queryValues []driver.Value
	queryErr    error
	execRows    int64
	execErr     error
	rowsErr     error
	beginErr    error
	commitErr   error
}

type stubSQLDriver struct{ state *stubSQLState }

func (database stubSQLDriver) Open(string) (driver.Conn, error) {
	return &stubSQLConnection{state: database.state}, nil
}

type stubSQLConnection struct{ state *stubSQLState }

func (*stubSQLConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("not supported")
}
func (*stubSQLConnection) Close() error { return nil }
func (connection *stubSQLConnection) Begin() (driver.Tx, error) {
	return connection.BeginTx(context.Background(), driver.TxOptions{})
}
func (connection *stubSQLConnection) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	connection.state.mu.Lock()
	defer connection.state.mu.Unlock()
	if connection.state.beginErr != nil {
		return nil, connection.state.beginErr
	}
	return stubSQLTransaction{state: connection.state}, nil
}
func (connection *stubSQLConnection) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	connection.state.mu.Lock()
	defer connection.state.mu.Unlock()
	if connection.state.queryErr != nil {
		return nil, connection.state.queryErr
	}
	values := append([]driver.Value(nil), connection.state.queryValues...)
	return &stubSQLRows{values: values}, nil
}
func (connection *stubSQLConnection) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	connection.state.mu.Lock()
	defer connection.state.mu.Unlock()
	if connection.state.execErr != nil {
		return nil, connection.state.execErr
	}
	return stubSQLResult{rows: connection.state.execRows, err: connection.state.rowsErr}, nil
}

type stubSQLTransaction struct{ state *stubSQLState }

func (transaction stubSQLTransaction) Commit() error {
	transaction.state.mu.Lock()
	defer transaction.state.mu.Unlock()
	return transaction.state.commitErr
}
func (stubSQLTransaction) Rollback() error { return nil }

type stubSQLRows struct {
	values []driver.Value
	done   bool
}

func (*stubSQLRows) Columns() []string { return []string{"uses", "max_uses", "expires_at", "expired"} }
func (*stubSQLRows) Close() error      { return nil }
func (rows *stubSQLRows) Next(destination []driver.Value) error {
	if rows.done || len(rows.values) == 0 {
		return io.EOF
	}
	copy(destination, rows.values)
	rows.done = true
	return nil
}

type stubSQLResult struct {
	rows int64
	err  error
}

func (stubSQLResult) LastInsertId() (int64, error) { return 0, errors.New("not supported") }
func (result stubSQLResult) RowsAffected() (int64, error) {
	return result.rows, result.err
}

type fakeRecord struct {
	uses      uint32
	maxUses   uint32
	expiresAt time.Time
	expired   bool
}

type fakeBackend struct {
	mu              sync.Mutex
	records         map[string]fakeRecord
	beginErr        error
	loadErr         error
	insertErr       error
	replaceErr      error
	cleanupErr      error
	cleanupRows     int64
	insertConflicts int
	commitErr       error
}

func newFakeBackend() *fakeBackend { return &fakeBackend{records: make(map[string]fakeRecord)} }

func (backend *fakeBackend) begin(ctx context.Context) (transaction, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if backend.beginErr != nil {
		return nil, backend.beginErr
	}
	backend.mu.Lock()
	return &fakeTransaction{backend: backend}, nil
}

func (backend *fakeBackend) expire(id string) {
	backend.mu.Lock()
	record := backend.records[id]
	record.expired = true
	backend.records[id] = record
	backend.mu.Unlock()
}

type fakeTransaction struct {
	backend *fakeBackend
	closed  bool
}

func (transaction *fakeTransaction) load(_ context.Context, id string) (storedConsumption, bool, error) {
	if transaction.backend.loadErr != nil {
		return storedConsumption{}, false, transaction.backend.loadErr
	}
	record, found := transaction.backend.records[id]
	return storedConsumption(record), found, nil
}

func (transaction *fakeTransaction) insert(_ context.Context, request capability.Consumption) (bool, error) {
	if transaction.backend.insertErr != nil {
		return false, transaction.backend.insertErr
	}
	if transaction.backend.insertConflicts > 0 {
		transaction.backend.insertConflicts--
		return false, nil
	}
	if _, found := transaction.backend.records[request.CapabilityID]; found {
		return false, nil
	}
	transaction.backend.records[request.CapabilityID] = fakeRecord{uses: 1, maxUses: request.MaxUses, expiresAt: request.ExpiresAt}
	return true, nil
}

func (transaction *fakeTransaction) replace(_ context.Context, request capability.Consumption, uses uint32) error {
	if transaction.backend.replaceErr != nil {
		return transaction.backend.replaceErr
	}
	transaction.backend.records[request.CapabilityID] = fakeRecord{uses: uses, maxUses: request.MaxUses, expiresAt: request.ExpiresAt}
	return nil
}

func (transaction *fakeTransaction) cleanup(context.Context, time.Time) (int64, error) {
	return transaction.backend.cleanupRows, transaction.backend.cleanupErr
}

func (transaction *fakeTransaction) Commit() error {
	transaction.close()
	return transaction.backend.commitErr
}

func (transaction *fakeTransaction) Rollback() error {
	transaction.close()
	return nil
}

func (transaction *fakeTransaction) close() {
	if !transaction.closed {
		transaction.closed = true
		transaction.backend.mu.Unlock()
	}
}
