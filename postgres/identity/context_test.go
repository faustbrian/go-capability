package identitycapability

import "context"

// nilContextForTest supplies deliberately unsupported caller input. Naming the
// negative fixture distinguishes denial tests from accidental nil callers.
func nilContextForTest() context.Context { return nil }
