package capability

// Grant is authenticated capability authority. Its contents are copied so
// caller mutation cannot widen a previously verified grant.
type Grant struct {
	payload Payload
	header  Header
}

// Use describes one concrete application operation to authorize.
type Use struct {
	Audience  string
	Subject   string
	Resource  string
	Operation string
	Tenant    string
	Caveats   map[string]string
}

// Payload returns a defensive copy of the authenticated payload.
func (grant Grant) Payload() Payload {
	return clonePayload(grant.payload)
}

// Header returns the authenticated key and algorithm metadata.
func (grant Grant) Header() Header { return grant.header }

// Authorize checks exact encoded authority separately from parsing and signature verification.
func (grant Grant) Authorize(use Use) error {
	if !contains(grant.payload.Audiences, use.Audience) ||
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
