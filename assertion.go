// This file is a transformed copy of: https://github.com/AthenZ/athenz-authorizer/blob/master/policy/assertion.go
package main

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// ErrDomainMismatch "Access denied due to domain mismatch between Resource and RoleToken"
	ErrDomainMismatch = fmt.Errorf("Access denied due to domain mismatch between Resource and RoleToken")

	// ErrDomainNotFound "Access denied due to domain not found in library cache"
	ErrDomainNotFound = fmt.Errorf("Access denied due to domain not found in library cache")

	// ErrNoMatch "Access denied due to no match to any of the assertions defined in domain policy file"
	ErrNoMatch = fmt.Errorf("Access denied due to no match to any of the assertions defined in domain policy file")

	// ErrInvalidPolicyResource "Access denied due to invalid/empty policy resources"
	ErrInvalidPolicyResource = fmt.Errorf("Access denied due to invalid/empty policy resources")

	// ErrDenyByPolicy "Access Check was explicitly denied"
	ErrDenyByPolicy = fmt.Errorf("Access Check was explicitly denied")

	// ErrDomainExpired "Access denied due to expired domain policy file"
	ErrDomainExpired = fmt.Errorf("Access denied due to expired domain policy file")

	// ErrFetchPolicy "Error fetching athenz policy"
	ErrFetchPolicy = fmt.Errorf("Error fetching athenz policy")
)

// AssertionValidator represents the refined assertion data use in policy checking
type AssertionValidator struct {
	ResourceDomain string         `json:"resource_domain"`
	ActionRegexp   *regexp.Regexp `json:"-"`
	ResourceRegexp *regexp.Regexp `json:"-"`
	Effect         error          `json:"effect"`

	Action               string `json:"action"`
	Resource             string `json:"resource"`
	ActionRegexpString   string `json:"action_regexp_string"`
	ResourceRegexpString string `json:"resource_regexp_string"`
}

// NewAssertionValidator returns the AssertionValidator object or error
func NewAssertionValidator(effect, action, resource string) (*AssertionValidator, error) {
	domres := strings.SplitN(resource, ":", 2)
	if len(domres) < 2 {
		return nil, fmt.Errorf("%s: %s", ErrInvalidPolicyResource, "assertion format not correct")
	}
	dom := domres[0]
	res := domres[1]

	ar, err := regexp.Compile(patternFromGlob(strings.ToLower(action)))
	if err != nil {
		return nil, fmt.Errorf("%s: %s", err, "assertion format not correct")
	}

	rr, err := regexp.Compile(patternFromGlob(strings.ToLower(res)))
	if err != nil {
		return nil, fmt.Errorf("%s: %s", err, "assertion format not correct")
	}

	return &AssertionValidator{
		ResourceDomain: dom,
		ActionRegexp:   ar,
		ResourceRegexp: rr,
		Effect: func() error {
			if strings.EqualFold("deny", effect) {
				return fmt.Errorf("%s: %s", ErrDenyByPolicy, "policy deny")
			}
			return nil
		}(),
		Action:               action,
		Resource:             res,
		ActionRegexpString:   ar.String(),
		ResourceRegexpString: rr.String(),
	}, nil
}

func isRegexMetaCharacter(target rune) bool {
	switch target {
	case '^':
	case '$':
	case '.':
	case '|':
	case '[':
	case '+':
	case '\\':
	case '(':
	case ')':
	case '{':
	default:
		return false
	}
	return true
}

func patternFromGlob(glob string) string {
	var sb strings.Builder
	sb.WriteString("^")
	for _, c := range glob {
		if c == '*' {
			sb.WriteString(".*")
		} else if c == '?' {
			sb.WriteString(".")
		} else {
			if isRegexMetaCharacter(c) {
				sb.WriteString("\\")
			}
			sb.WriteRune(c)
		}
	}
	sb.WriteString("$")
	return sb.String()
}
