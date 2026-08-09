package capability

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const (
	urlProfileCaveat = "cap.url.profile"
	urlDigestCaveat  = "cap.url.body-sha256"
)

// URLProfile fixes every URL component whose interpretation affects authority.
// QueryParameters is an allowlist; duplicate parameters are always rejected.
type URLProfile struct {
	Name               string
	SignatureParameter string
	AllowRelative      bool
	AllowedSchemes     []string
	AllowedAuthorities []string
	QueryParameters    []string
	RequireBodyDigest  bool
}

// URLRequest contains the already selected external request representation.
// BodyDigest, when required, is exactly a SHA-256 digest rather than body bytes.
type URLRequest struct {
	Method     string
	RawURL     string
	BodyDigest []byte
}

// Validate checks that a profile is deterministic and bounded under limits.
func (profile URLProfile) Validate(limits Limits) error {
	if err := validateLimits(limits); err != nil {
		return err
	}
	return validateURLProfile(profile, limits)
}

// SignURL binds a capability to a canonical URL and inserts the token in the
// profile's signature parameter. Payload Resource and Operation must be empty
// because this function owns those authority fields.
func SignURL(
	ctx context.Context,
	payload Payload,
	request URLRequest,
	profile URLProfile,
	signer Signer,
	limits Limits,
) (string, error) {
	if payload.Resource != "" || payload.Operation != "" {
		return "", invalidField("URL authority")
	}
	canonical, transport, _, err := canonicalURL(request, profile, limits, false)
	if err != nil {
		return "", err
	}
	payload.Resource = canonical
	payload.Operation = request.Method
	payload.Caveats = cloneMap(payload.Caveats)
	_, hasProfileCaveat := payload.Caveats[urlProfileCaveat]
	_, hasDigestCaveat := payload.Caveats[urlDigestCaveat]
	if hasProfileCaveat || hasDigestCaveat {
		return "", invalidField("reserved URL caveat")
	}
	if payload.Caveats == nil {
		payload.Caveats = make(map[string]string, 2)
	}
	payload.Caveats[urlProfileCaveat] = profile.Name
	if profile.RequireBodyDigest {
		payload.Caveats[urlDigestCaveat] = base64.RawURLEncoding.EncodeToString(request.BodyDigest)
	}
	token, err := Issue(ctx, payload, signer, limits)
	if err != nil {
		return "", err
	}
	u, _ := url.Parse(transport)
	values := u.Query()
	values.Set(profile.SignatureParameter, token)
	u.RawQuery = values.Encode()
	return u.String(), nil
}

// VerifyURL authenticates the embedded capability and independently checks its
// method, authority, path, query, profile, and optional body-digest binding.
func VerifyURL(
	ctx context.Context,
	request URLRequest,
	profile URLProfile,
	resolver Resolver,
	options VerifyOptions,
) (Grant, error) {
	canonical, _, token, err := canonicalURL(request, profile, options.Limits, true)
	if err != nil {
		return Grant{}, err
	}
	grant, err := Verify(ctx, token, resolver, options)
	if err != nil {
		return Grant{}, err
	}
	payload := grant.payload
	if payload.Resource != canonical || payload.Operation != request.Method ||
		payload.Caveats[urlProfileCaveat] != profile.Name {
		return Grant{}, ErrURLBinding
	}
	if profile.RequireBodyDigest {
		expected := []byte(payload.Caveats[urlDigestCaveat])
		actual := []byte(base64.RawURLEncoding.EncodeToString(request.BodyDigest))
		if len(expected) != len(actual) || subtle.ConstantTimeCompare(expected, actual) != 1 {
			return Grant{}, ErrURLBinding
		}
	} else if _, exists := payload.Caveats[urlDigestCaveat]; exists {
		return Grant{}, ErrURLBinding
	}
	grant.payload = clonePayload(grant.payload)
	delete(grant.payload.Caveats, urlProfileCaveat)
	delete(grant.payload.Caveats, urlDigestCaveat)
	return grant, nil
}

func canonicalURL(request URLRequest, profile URLProfile, limits Limits, signed bool) (string, string, string, error) {
	if err := validateLimits(limits); err != nil {
		return "", "", "", err
	}
	if err := validateURLProfile(profile, limits); err != nil {
		return "", "", "", err
	}
	if !validMethod(request.Method) || len(request.RawURL) == 0 || len(request.RawURL) > limits.MaxTokenBytes*2 {
		return "", "", "", ErrInvalidURL
	}
	if profile.RequireBodyDigest != (len(request.BodyDigest) == 32) {
		return "", "", "", ErrInvalidURL
	}
	u, err := url.Parse(request.RawURL)
	if err != nil {
		return "", "", "", ErrInvalidURL
	}
	if u.Opaque != "" {
		return "", "", "", ErrInvalidURL
	}
	if u.Fragment != "" {
		return "", "", "", ErrInvalidURL
	}
	if u.ForceQuery {
		return "", "", "", ErrInvalidURL
	}
	if u.User != nil {
		return "", "", "", ErrInvalidURL
	}
	base, err := canonicalURLBase(u, profile)
	if err != nil {
		return "", "", "", err
	}
	values, err := parseUniqueQuery(u.RawQuery)
	if err != nil {
		return "", "", "", err
	}
	receivedQuery := values.Encode()
	token := ""
	if signed {
		token = values.Get(profile.SignatureParameter)
		if token == "" {
			return "", "", "", ErrInvalidURL
		}
		values.Del(profile.SignatureParameter)
	} else if values.Has(profile.SignatureParameter) {
		return "", "", "", ErrInvalidURL
	}
	allowed := make(map[string]struct{}, len(profile.QueryParameters))
	for _, name := range profile.QueryParameters {
		allowed[name] = struct{}{}
	}
	for name := range values {
		if _, exists := allowed[name]; !exists {
			return "", "", "", ErrInvalidURL
		}
	}
	canonicalQuery := values.Encode()
	canonical := base
	if canonicalQuery != "" {
		canonical += "?" + canonicalQuery
	}
	transport := canonical
	if signed {
		if u.RawQuery != receivedQuery {
			return "", "", "", ErrInvalidURL
		}
		u.RawQuery = ""
		u.ForceQuery = false
		if u.String() != base {
			return "", "", "", ErrInvalidURL
		}
	}
	return canonical, transport, token, nil
}

func validateURLProfile(profile URLProfile, limits Limits) error {
	if !validText(profile.Name, limits.MaxFieldBytes, true) ||
		!validText(profile.SignatureParameter, limits.MaxFieldBytes, true) {
		return ErrInvalidConfiguration
	}
	if len(profile.AllowedSchemes) == 0 && !profile.AllowRelative {
		return ErrInvalidConfiguration
	}
	if (len(profile.AllowedSchemes) == 0) != (len(profile.AllowedAuthorities) == 0) {
		return ErrInvalidConfiguration
	}
	if !strictSortedUnique(profile.AllowedSchemes) || !strictSortedUnique(profile.AllowedAuthorities) ||
		!strictSortedUnique(profile.QueryParameters) {
		return ErrInvalidConfiguration
	}
	for _, scheme := range profile.AllowedSchemes {
		if scheme != "https" && scheme != "http" {
			return ErrInvalidConfiguration
		}
	}
	for _, authority := range profile.AllowedAuthorities {
		if strings.ToLower(authority) != authority {
			return ErrInvalidConfiguration
		}
		if !ascii(authority) {
			return ErrInvalidConfiguration
		}
		if !canonicalProfileAuthority(authority, profile.AllowedSchemes) {
			return ErrInvalidConfiguration
		}
	}
	for _, name := range profile.QueryParameters {
		if !validText(name, limits.MaxFieldBytes, true) || name == profile.SignatureParameter {
			return ErrInvalidConfiguration
		}
	}
	return nil
}

func canonicalProfileAuthority(authority string, schemes []string) bool {
	for _, scheme := range schemes {
		if profileAuthorityValidForScheme(authority, scheme) {
			return true
		}
	}
	return false
}

func profileAuthorityValidForScheme(authority, scheme string) bool {
	candidate, err := url.Parse(scheme + "://" + authority + "/")
	if err != nil {
		return false
	}
	if candidate.User != nil {
		return false
	}
	if candidate.Host != authority {
		return false
	}
	canonical, err := canonicalAuthority(candidate)
	if err != nil {
		return false
	}
	return canonical == authority
}

func canonicalURLBase(u *url.URL, profile URLProfile) (string, error) {
	path, err := canonicalPath(u)
	if err != nil {
		return "", err
	}
	if !u.IsAbs() {
		if !profile.AllowRelative || u.Host != "" {
			return "", ErrInvalidURL
		}
		return path, nil
	}
	if u.Scheme != strings.ToLower(u.Scheme) {
		return "", ErrInvalidURL
	}
	if !containsString(profile.AllowedSchemes, u.Scheme) {
		return "", ErrInvalidURL
	}
	authority, err := canonicalAuthority(u)
	if err != nil {
		return "", ErrInvalidURL
	}
	if !containsString(profile.AllowedAuthorities, authority) {
		return "", ErrInvalidURL
	}
	return u.Scheme + "://" + authority + path, nil
}

func canonicalAuthority(u *url.URL) (string, error) {
	hostname := u.Hostname()
	if hostname == "" || !ascii(hostname) || strings.HasSuffix(hostname, ".") {
		return "", ErrInvalidURL
	}
	hostname = strings.ToLower(hostname)
	port := u.Port()
	if port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
			return "", ErrInvalidURL
		}
		if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
			port = ""
		}
	}
	if strings.Contains(hostname, ":") {
		if port == "" {
			return "[" + hostname + "]", nil
		}
		return net.JoinHostPort(hostname, port), nil
	}
	if port != "" {
		return net.JoinHostPort(hostname, port), nil
	}
	return hostname, nil
}

func canonicalPath(u *url.URL) (string, error) {
	decoded := u.Path
	if decoded == "" {
		decoded = "/"
	}
	if !strings.HasPrefix(decoded, "/") || strings.Contains(decoded, "\\") {
		return "", ErrInvalidURL
	}
	parts := strings.Split(strings.TrimPrefix(decoded, "/"), "/")
	encoded := make([]string, len(parts))
	for index, part := range parts {
		if part == "." || part == ".." || (part == "" && index+1 < len(parts)) {
			return "", ErrInvalidURL
		}
		encoded[index] = url.PathEscape(part)
	}
	path := "/" + strings.Join(encoded, "/")
	escaped := strings.ToLower(u.EscapedPath())
	if strings.Contains(escaped, "%2f") {
		return "", ErrInvalidURL
	}
	return path, nil
}

func parseUniqueQuery(raw string) (url.Values, error) {
	values := make(url.Values)
	if raw == "" {
		return values, nil
	}
	for _, field := range strings.Split(raw, "&") {
		if field == "" {
			return nil, ErrInvalidURL
		}
		pair := strings.SplitN(field, "=", 2)
		name, err := url.QueryUnescape(pair[0])
		if err != nil || name == "" {
			return nil, ErrInvalidURL
		}
		value := ""
		if len(pair) == 2 {
			value, err = url.QueryUnescape(pair[1])
			if err != nil {
				return nil, ErrInvalidURL
			}
		}
		if _, exists := values[name]; exists {
			return nil, ErrInvalidURL
		}
		values.Set(name, value)
	}
	return values, nil
}

func validMethod(method string) bool {
	if method == "" || method != strings.ToUpper(method) {
		return false
	}
	for _, character := range method {
		if character <= 0x20 || character >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}", character) {
			return false
		}
	}
	return true
}

func strictSortedUnique(values []string) bool {
	for index, value := range values {
		if value == "" || (index > 0 && values[index-1] >= value) {
			return false
		}
	}
	return true
}

func containsString(values []string, candidate string) bool {
	index := sort.SearchStrings(values, candidate)
	return index < len(values) && values[index] == candidate
}

func ascii(value string) bool {
	for _, character := range value {
		if character > 0x7f {
			return false
		}
	}
	return true
}
