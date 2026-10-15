package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func identityFixture(t *testing.T) (ServiceConfig, string) {
	t.Helper()
	key := bytes.Repeat([]byte{42}, 32)
	signer, err := NewHMACSHA256Signer("key", key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewHMACSHA256Verifier(key)
	if err != nil {
		t.Fatal(err)
	}
	config := ServiceConfig{Issuer: internalPayload().Issuer, Signer: signer, Resolver: ResolverFunc(func(context.Context, string, Algorithm) (ResolvedKey, error) {
		return ResolvedKey{Issuer: internalPayload().Issuer, Verifier: verifier}, nil
	}), Clock: func() time.Time { return internalPayload().IssuedAt }, Limits: DefaultLimits()}
	token, err := Issue(context.Background(), internalPayload(), signer, config.Limits)
	if err != nil {
		t.Fatal(err)
	}
	return config, token
}

func mustProof(t *testing.T, token string) Proof {
	t.Helper()
	proof, err := ParseProof(token, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestIdentityTransferFailureCustody(t *testing.T) {
	_, token := identityFixture(t)
	for _, panicValue := range []bool{false, true} {
		proof := mustProof(t, token)
		var borrowed []byte
		calls := 0
		err := proof.Transfer(context.Background(), func(_ context.Context, b []byte) error {
			borrowed = b
			calls++
			if panicValue {
				panic("private callback diagnostic")
			}
			return errors.New("private callback diagnostic")
		})
		if err == nil {
			t.Fatal("callback failure reported success")
		}
		if err != ErrProofTransferFailed || strings.Contains(err.Error(), "private") || calls != 1 {
			t.Fatalf("unsafe callback result %v", err)
		}
		if borrowed == nil {
			t.Fatal("callback borrow not observed")
		}
		if !bytes.Equal(borrowed[:cap(borrowed)], make([]byte, cap(borrowed))) {
			t.Fatal("borrow capacity retained")
		}
		if _, err := proof.snapshot(); err != ErrInvalidToken {
			t.Fatal("failed transfer retained authority")
		}
	}
	for _, classification := range []error{context.Canceled, context.DeadlineExceeded} {
		err := mustProof(t, token).Transfer(context.Background(), func(context.Context, []byte) error { return fmt.Errorf("private: %w", classification) })
		if err == nil {
			t.Fatal("callback error reported success")
		}
		if !errors.Is(err, classification) || !errors.Is(err, ErrProofTransferFailed) || strings.Contains(err.Error(), "private") {
			t.Fatalf("classification %v", err)
		}
	}
	proof := mustProof(t, token)
	callback := func(context.Context, []byte) error { t.Error("invalid invocation"); return nil }
	var nilContext context.Context
	if err := proof.Transfer(nilContext, callback); err != ErrInvalidConfiguration {
		t.Fatal(err)
	}
	if err := proof.Transfer(context.Background(), nil); err != ErrInvalidConfiguration {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := proof.Transfer(ctx, callback); err != context.Canceled {
		t.Fatal(err)
	}
	if _, err := proof.snapshot(); err != nil {
		t.Fatal("pre-cancellation lost custody")
	}
	if err := (Proof{}).Transfer(context.Background(), callback); err != ErrInvalidToken {
		t.Fatal(err)
	}
	if _, err := (Proof{}).snapshot(); err != ErrInvalidToken {
		t.Fatal(err)
	}
}

func TestIdentityTransferPanicCancellationClassification(t *testing.T) {
	_, token := identityFixture(t)
	for _, classification := range []error{context.Canceled, context.DeadlineExceeded} {
		err := mustProof(t, token).Transfer(context.Background(), func(context.Context, []byte) error { panic(fmt.Errorf("private: %w", classification)) })
		if err == nil {
			t.Fatal("callback panic reported success")
		}
		if !errors.Is(err, classification) || !errors.Is(err, ErrProofTransferFailed) || strings.Contains(err.Error(), "private") {
			t.Fatalf("lost safe panic classification %v", err)
		}
	}
}

type cancelOnSecondCheck struct {
	context.Context
	calls int
}

type custodyInspectingContext struct {
	context.Context
	state  *proofState
	locked bool
}

func (ctx *custodyInspectingContext) Err() error {
	if !ctx.state.mu.TryLock() {
		ctx.locked = true
		return context.Canceled
	}
	ctx.state.mu.Unlock()
	return nil
}
func TestIdentityContextMethodsRunOutsideCustodyLock(t *testing.T) {
	_, token := identityFixture(t)
	proof := mustProof(t, token)
	ctx := &custodyInspectingContext{Context: context.Background(), state: proof.state}
	err := proof.Transfer(ctx, func(context.Context, []byte) error { return nil })
	if ctx.locked || err != nil {
		t.Fatalf("caller context invoked under custody lock: %v", err)
	}
}

type panicClassifier struct{}

func (panicClassifier) Error() string { return "private" }
func (panicClassifier) Is(error) bool { panic("private classifier") }
func TestIdentityTransferClassifierPanicIsRedacted(t *testing.T) {
	_, token := identityFixture(t)
	for _, panicCallback := range []bool{false, true} {
		proof := mustProof(t, token)
		var borrowed []byte
		err := proof.Transfer(context.Background(), func(_ context.Context, b []byte) error {
			borrowed = b
			if panicCallback {
				panic(panicClassifier{})
			}
			return panicClassifier{}
		})
		if err != ErrProofTransferFailed {
			t.Fatal(err)
		}
		if borrowed == nil {
			t.Fatal("callback borrow not observed")
		}
		if !bytes.Equal(borrowed[:cap(borrowed)], make([]byte, cap(borrowed))) {
			t.Fatal("classifier panic retained secret")
		}
	}
}

func (c *cancelOnSecondCheck) Err() error {
	c.calls++
	if c.calls > 1 {
		return context.Canceled
	}
	return nil
}

func TestIdentityTransferCancellationUnderLockPreservesCustody(t *testing.T) {
	_, token := identityFixture(t)
	proof := mustProof(t, token)
	ctx := &cancelOnSecondCheck{Context: context.Background()}
	if err := proof.Transfer(ctx, func(context.Context, []byte) error { t.Error("canceled callback ran"); return nil }); err != context.Canceled {
		t.Fatal(err)
	}
	if _, err := proof.snapshot(); err != nil {
		t.Fatal(err)
	}
}

type changingKeySigner struct{ calls int }

func (*changingKeySigner) Algorithm() Algorithm { return HMACSHA256 }
func (s *changingKeySigner) KeyID() string {
	s.calls++
	if s.calls >= 3 {
		return strings.Repeat("x", 257)
	}
	return "key"
}
func (*changingKeySigner) Sign(context.Context, []byte) ([]byte, error) {
	return []byte("signature"), nil
}

func TestIdentityServiceRejectsNonReferenceableIssue(t *testing.T) {
	config, _ := identityFixture(t)
	config.Limits.MaxFieldBytes = 512
	s, err := NewService(config)
	if err != nil {
		t.Fatal(err)
	}
	p := internalPayload()
	p.ID = strings.Repeat("x", 257)
	if proof, r, err := s.Issue(context.Background(), p); err != ErrInvalidPayload || proof.state != nil || r != (Reference{}) {
		t.Fatal("unbounded reference")
	}
	config.Signer = &changingKeySigner{}
	s, err = NewService(config)
	if err != nil {
		t.Fatal(err)
	}
	if proof, r, err := s.Issue(context.Background(), internalPayload()); err == nil || proof.state != nil || r != (Reference{}) {
		t.Fatal("malformed signing metadata passed structural parse")
	}
}

func TestIdentityTransferConcurrentAndSnapshot(t *testing.T) {
	config, token := identityFixture(t)
	proof := mustProof(t, token)
	start := make(chan struct{})
	entered := make(chan struct{})
	resume := make(chan struct{})
	config.Resolver = ResolverFunc(func(context.Context, string, Algorithm) (ResolvedKey, error) {
		close(entered)
		<-resume
		return configVerifier(t), nil
	})
	s, err := NewService(config)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	done := make(chan struct{})
	var resumeOnce sync.Once
	release := func() { resumeOnce.Do(func() { close(resume) }) }
	t.Cleanup(func() {
		release()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("verification goroutine did not finish")
		}
	})
	go func() {
		defer close(done)
		_, err := s.Verify(context.Background(), proof, Purpose(internalPayload().Operation), internalPayload().Audiences[0])
		result <- err
	}()
	select {
	case <-entered:
	case err := <-result:
		t.Fatalf("verification failed before snapshot barrier: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("verification did not reach snapshot barrier")
	}
	const contenders = 12
	results := make(chan error, contenders)
	var wg sync.WaitGroup
	for range contenders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if err != ErrInvalidToken {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("transfer winners %d", winners)
	}
	release()
	if err := <-result; err != nil {
		t.Fatalf("earlier snapshot rejected %v", err)
	}
	if _, err := s.Verify(context.Background(), proof, Purpose(internalPayload().Operation), internalPayload().Audiences[0]); err != ErrInvalidToken {
		t.Fatalf("later snapshot %v", err)
	}
}

func configVerifier(t *testing.T) ResolvedKey {
	t.Helper()
	verifier, err := NewHMACSHA256Verifier(bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return ResolvedKey{Issuer: internalPayload().Issuer, Verifier: verifier}
}

func TestIdentityProofRepresentations(t *testing.T) {
	_, token := identityFixture(t)
	proof := mustProof(t, token)
	for _, value := range []any{proof, &proof, []Proof{proof}, map[string]Proof{"proof": proof}, struct{ Proof Proof }{proof}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
			if strings.Contains(fmt.Sprintf(verb, value), "cap1") {
				t.Fatal("format disclosure")
			}
		}
		encoded, err := json.Marshal(value)
		if err != nil || strings.Contains(string(encoded), "cap1") {
			t.Fatalf("JSON disclosure %v", err)
		}
	}
	var log bytes.Buffer
	slog.New(slog.NewJSONHandler(&log, nil)).Info("custody", "proof", proof, "pointer", &proof)
	if strings.Contains(log.String(), "cap1") || !strings.Contains(log.String(), "REDACTED") {
		t.Fatal("log disclosure")
	}
}

func TestIdentityConstructorAndServiceFailures(t *testing.T) {
	config, token := identityFixture(t)
	for _, mutate := range []func(*ServiceConfig){func(c *ServiceConfig) { c.Signer = nil }, func(c *ServiceConfig) { c.Resolver = nil }, func(c *ServiceConfig) { c.Clock = nil }, func(c *ServiceConfig) { c.Skew = -1 }, func(c *ServiceConfig) { c.Limits = Limits{} }, func(c *ServiceConfig) { c.Signer = stubSigner{algorithm: "bad", keyID: "key"} }, func(c *ServiceConfig) { c.Signer = stubSigner{algorithm: HMACSHA256, keyID: ""} }} {
		bad := config
		mutate(&bad)
		if s, err := NewService(bad); err != ErrInvalidConfiguration || s != nil {
			t.Fatalf("invalid service %v", err)
		}
	}
	s, err := NewService(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range []Payload{{}, func() Payload { p := internalPayload(); p.Operation = "*"; return p }(), func() Payload { p := internalPayload(); p.ExpiresAt = p.IssuedAt; return p }()} {
		if p, r, err := s.Issue(context.Background(), payload); err == nil || p.state != nil || r != (Reference{}) {
			t.Fatal("invalid issue nonzero result")
		}
	}
	var nilContext context.Context
	if _, _, err := s.Issue(nilContext, internalPayload()); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal(err)
	}
	zeroClock := config
	zeroClock.Clock = func() time.Time { return time.Time{} }
	z, err := NewService(zeroClock)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := z.Issue(context.Background(), internalPayload()); err != ErrInvalidConfiguration {
		t.Fatal(err)
	}
	for _, call := range []func() (Grant, error){func() (Grant, error) { return s.Verify(nilContext, mustProof(t, token), "download", "api") }, func() (Grant, error) { return s.Verify(context.Background(), Proof{}, "download", "api") }, func() (Grant, error) { return s.Verify(context.Background(), mustProof(t, token), "*", "api") }, func() (Grant, error) { return s.Verify(context.Background(), mustProof(t, token), "download", "") }, func() (Grant, error) { return s.Verify(context.Background(), mustProof(t, token), "different", "api") }, func() (Grant, error) {
		return s.Verify(context.Background(), mustProof(t, token), Purpose(internalPayload().Operation), "different")
	}} {
		g, err := call()
		if err == nil || g.Payload().ID != "" {
			t.Fatal("invalid verification returned authority")
		}
	}
	for _, configure := range []func(*ServiceConfig){func(c *ServiceConfig) { c.Clock = func() time.Time { return internalPayload().ExpiresAt } }, func(c *ServiceConfig) {
		c.Revocations = RevocationCheckerFunc(func(context.Context, RevocationQuery) (bool, error) { return true, nil })
	}, func(c *ServiceConfig) {
		c.Revocations = RevocationCheckerFunc(func(context.Context, RevocationQuery) (bool, error) { return false, errors.New("private") })
	}} {
		bad := config
		configure(&bad)
		s, err := NewService(bad)
		if err != nil {
			t.Fatal(err)
		}
		g, err := s.Verify(context.Background(), mustProof(t, token), Purpose(internalPayload().Operation), internalPayload().Audiences[0])
		if err == nil || g.Payload().ID != "" {
			t.Fatal("failed-open verification")
		}
	}
}

func TestIdentityTransferNilPanic(t *testing.T) {
	if os.Getenv("CAPABILITY_NILPANIC_CHILD") == "1" {
		_, token := identityFixture(t)
		proof := mustProof(t, token)
		var borrowed []byte
		err := proof.Transfer(context.Background(), func(_ context.Context, b []byte) error { borrowed = b; panic(nil) })
		if err != ErrProofTransferFailed {
			t.Fatalf("nil panic reported transport success: %v", err)
		}
		if borrowed == nil {
			t.Fatal("callback borrow not observed")
		}
		if !bytes.Equal(borrowed[:cap(borrowed)], make([]byte, cap(borrowed))) {
			t.Fatal("nil panic retained secret")
		}
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestIdentityTransferNilPanic$")
	command.Env = append(os.Environ(), "GODEBUG=panicnil=1", "CAPABILITY_NILPANIC_CHILD=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("legacy nil-panic boundary failed: %v: %s", err, output)
	}
}

func TestIdentityPurposeReferenceAndIngressBounds(t *testing.T) {
	for _, value := range []string{"a", "A", "0", strings.Repeat("z", 128), "a.Z-_09"} {
		if _, err := NewPurpose(value); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{strings.Repeat("z", 129), "_a", "a\n", "a\x7f"} {
		if _, err := NewPurpose(value); err != ErrInvalidPayload {
			t.Fatal(err)
		}
	}
	digest := [32]byte{1}
	expiry := time.Unix(123, 0).UTC()
	for _, input := range []Reference{{"", "download", digest, expiry}, {strings.Repeat("i", 257), "download", digest, expiry}, {"id", "*", digest, expiry}, {"id", "download", [32]byte{}, expiry}, {"id", "download", digest, time.Time{}}, {"id", "download", digest, time.Unix(0, 0).UTC()}, {"id", "download", digest, expiry.Add(time.Nanosecond)}, {"id", "download", digest, expiry.In(time.FixedZone("offset", 3600))}} {
		if r, err := NewReference(input.CapabilityID, input.Purpose, input.Digest, input.ExpiresAt); err != ErrInvalidPayload || r != (Reference{}) {
			t.Fatal("invalid reference")
		}
	}
	if r, err := NewReference("id", "download", digest, expiry); err != nil || r.CapabilityID != "id" {
		t.Fatal(err)
	}
	if _, err := NewReference(strings.Repeat("i", 256), "download", digest, expiry); err != nil {
		t.Fatal("maximum ID rejected")
	}
	_, token := identityFixture(t)
	for _, limits := range []Limits{{}, func() Limits { l := DefaultLimits(); l.MaxTokenBytes = len(token) - 1; return l }()} {
		if p, err := ParseProof(token, limits); err == nil || p.state != nil {
			t.Fatal("unbounded parse")
		}
	}
	if p, err := ParseProof("invalid", DefaultLimits()); err == nil || p.state != nil {
		t.Fatal("invalid parse")
	}
}
