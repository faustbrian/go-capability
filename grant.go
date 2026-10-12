package capability

// Grant is authenticated capability authority. Its contents are copied so
// caller mutation cannot widen a previously verified grant.
// Zero Grant cannot authorize or consume. Value copies support concurrent reads
// with immutable Use inputs; they do not recheck time, revocation or key policy.
// Reverify before later effects as application policy requires.
type Grant struct {
	payload Payload
	header  Header
}

// Use describes one concrete application operation to authorize.
// Use fields must come from trusted application context rather than echoed token
// claims. Subject must be independently authenticated; Caveats stays borrowed
// during Authorize.
type Use struct {
	// Issuer must match the application-selected nonempty issuer exactly.
	Issuer string
	// Audience must equal one authenticated audience.
	Audience string
	// Subject must match subject-bound grants; bearer grants do not check it.
	Subject string
	// Resource must equal authenticated resource bytes exactly.
	Resource string
	// Operation must equal authenticated operation bytes exactly.
	Operation string
	// Tenant must equal authenticated tenant, including empty.
	Tenant string
	// Caveats is borrowed attempted-use data; every encoded caveat must match, extras are
	// ignored.
	Caveats map[string]string
}

// Payload returns a defensive copy of the authenticated payload.
func (grant Grant) Payload() Payload {
	return clonePayload(grant.payload)
}

// Header returns the authenticated key and algorithm metadata.
func (grant Grant) Header() Header { return grant.header }

// Authorize compares exact required authority under DEC-005. Any mismatch
// returns ErrUnauthorized; extra use caveats are ignored and bearer grants do
// not check subject. No clock, consumption, revocation or protected business
// operation runs here.
func (grant Grant) Authorize(use Use) error {
	if use.Issuer == "" || grant.payload.Issuer != use.Issuer ||
		!contains(grant.payload.Audiences, use.Audience) ||
		grant.payload.Resource != use.Resource || grant.payload.Operation != use.Operation ||
		grant.payload.Tenant != use.Tenant ||
		(!grant.payload.Bearer && grant.payload.Subject != use.Subject) {
		return ErrUnauthorized
	}
	for key, value := range grant.payload.Caveats {
		if use.Caveats[key] != value {
			return ErrUnauthorized
		}
	}
	return nil
}

func newGrant(payload Payload, header Header) Grant {
	return Grant{payload: clonePayload(payload), header: header}
}

func clonePayload(payload Payload) Payload {
	payload.Audiences = append([]string(nil), payload.Audiences...)
	payload.Caveats = cloneMap(payload.Caveats)
	return payload
}

func contains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
