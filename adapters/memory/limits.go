package capabilitymemory

// StoreLimits bounds one store's retained records and owned string bytes.
// Revocations share the allowance across all five revocation boundaries.
type StoreLimits struct {
	// MaxRecords is the aggregate number of retained records, including expired
	// replay records until removed. It must be positive.
	MaxRecords int
	// MaxStringBytes bounds the sum of each retained key's string lengths and
	// each operation's input strings before hashing. It must be positive. This
	// excludes map/record/allocator overhead and caller-owned backing storage.
	MaxStringBytes int
}

// DefaultStoreLimits returns finite process-local defaults: 10,000 records
// and 4 MiB of retained string bytes. Map and record overhead is additional.
func DefaultStoreLimits() StoreLimits {
	return StoreLimits{MaxRecords: 10_000, MaxStringBytes: 4 << 20}
}

// admission is protected by the owning store's mutex. Bytes count each newly
// owned string occurrence, not map overhead or the caller's input storage.
type admission struct {
	limits               StoreLimits
	records, stringBytes int
}

// size rejects oversized input before copying or map hashing. Subtraction
// keeps arithmetic bounded even for caller-selected limits near max int.
func (budget *admission) size(values ...string) (int, bool) {
	size := 0
	for _, value := range values {
		if len(value) > budget.limits.MaxStringBytes-size {
			return 0, false
		}
		size += len(value)
	}
	return size, true
}

func (budget *admission) reserve(size int) bool {
	if budget.records >= budget.limits.MaxRecords || size > budget.limits.MaxStringBytes-budget.stringBytes {
		return false
	}
	budget.records++
	budget.stringBytes += size
	return true
}

func (budget *admission) release(size int) {
	budget.records--
	budget.stringBytes -= size
}
