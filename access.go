package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
)

var (
	ErrInvalidJWT            = &customErr{"invalid jwt"}
	ErrInvalidJWTPayload     = &customErr{"invalid jwt payload"}
	ErrInvalidJWTPayloadJson = &customErr{"invalid jwt payload json"}
)

type customErr struct{ s string }

func (e *customErr) Error() string          { return e.s }
func (e *customErr) Errorf(err error) error { return fmt.Errorf("%s: %s", e.s, err) }

// Extract aud (string) and scopes ([]string) from the JWT
func extractAudAndScopesFromJWT(jwt string) (string, []string, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return "", nil, ErrInvalidJWT
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, ErrInvalidJWTPayload.Errorf(err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return "", nil, ErrInvalidJWTPayloadJson.Errorf(err)
	}
	// Audience
	var aud string
	switch v := payload["aud"].(type) {
	case string:
		aud = v
	case []interface{}:
		if len(v) > 0 {
			if str, ok := v[0].(string); ok {
				aud = str
			}
		}
	}
	// Scopes from "scope" (CSV string) and/or "scp" (array)
	var scopes []string
	if s, ok := payload["scope"].(string); ok && s != "" {
		for _, scope := range strings.Split(s, ",") {
			scopes = append(scopes, strings.TrimSpace(scope))
		}
	}
	if arr, ok := payload["scp"].([]interface{}); ok {
		for _, item := range arr {
			if str, ok := item.(string); ok {
				scopes = append(scopes, str)
			}
		}
	}
	return aud, scopes, nil
}

// Returns all assertions matches with the roles in the scopes.
func getRoleAssertions(audience string, scopes []string, jws *JwsPolicyPayload) []Assertion {
	if len(scopes) == 0 {
		return nil
	}
	roleSet := make(map[string]Assertion)
	for _, policy := range jws.PolicyData.Policies {
		for _, assertion := range policy.Assertions {
			roleSet[assertion.Role] = assertion
		}
	}
	var assertions []Assertion
	for _, scope := range scopes {
		role := audience + ":role." + scope
		if _, found := roleSet[role]; found {
			assertion := roleSet[role]
			proxywasm.LogDebugf("assertion found for role: request[%s], assertion[%#v]", role, assertion)
			assertions = append(assertions, assertion)
		}
	}
	return assertions
}

// Returns true if the assertions match with the request
func authorizePolicyAccess(audience, action, resource string, assertions []Assertion) bool {
	if len(assertions) == 0 {
		return false
	}
	for _, a := range assertions {
		proxywasm.LogDebugf("checking assertion with request: request{action[%s], resource[%s]}, assertion{effect[%s], action[%s], resource[%s]}", action, audience+":"+resource, a.Effect, a.Action, a.Resource)
		validator, err := NewAssertionValidator(a.Effect, a.Action, a.Resource)
		if err != nil {
			proxywasm.LogWarnf("assertion validator failed to initialize: effect[%s], action[%s], resource[%s]", a.Effect, a.Action, a.Resource)
			return false
		}
		// deny policies come first in rolePolicies, so it will return first before allow policies is checked
		if strings.EqualFold(validator.ResourceDomain, audience) &&
			validator.ActionRegexp.MatchString(strings.ToLower(action)) &&
			validator.ResourceRegexp.MatchString(strings.ToLower(resource)) {
			proxywasm.LogDebugf("assertion matched with request: action[%s], resource[%s], effect[%v]", action, resource, (validator.Effect == nil))
			if validator.Effect == nil {
				return true
			}
		}
	}
	return false
}
