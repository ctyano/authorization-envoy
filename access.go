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

func checkCoarseGrainedAuthorization(ctx *httpContext, aud string, scopes []string) bool {
	matchedRole := ""
constraintsCheck:
	for _, c := range ctx.plugin.constraints {
		if c.Domain == aud {
			for _, scope := range scopes {
				if c.Role == scope {
					matchedRole = aud + ":role." + scope
					break constraintsCheck
				}
			}
		}
	}
	// Compare audience and scopes
	if matchedRole == "" {
		proxywasm.LogWarnf("forbidden: audience and scopes mismatch: audience[%s], scopes[%#v], expected[%#v]", aud, scopes, ctx.plugin.constraints)
		proxywasm.SendHttpResponse(403, nil, []byte("Forbidden: audience and scopes mismatch"), -1)
		return false
	}
	return true
}

func checkFineGrainedAuthorization(ctx *httpContext, aud string, scopes []string) bool {
	var matchedJws *JwsPolicyPayload
	for _, jws := range ctx.plugin.policy {
		// Compare audience
		if strings.EqualFold(aud, jws.PolicyData.Domain) {
			matchedJws = jws
		}
	}
	if matchedJws == nil {
		proxywasm.LogWarnf("forbidden: audience domain not found in JWS payloads: audience[%s], matched JWS[%#v]", aud, matchedJws)
		proxywasm.SendHttpResponse(403, nil, []byte("Forbidden: audience mismatch"), -1)
		return false
	}
	// Compare scopes (scope and scp) with all roles in assertions
	var assertions []Assertion
	if assertions = getRoleAssertions(aud, scopes, matchedJws); assertions == nil {
		proxywasm.LogWarnf("forbidden: scope(s) not allowed: aud[%s], scopes[%#v], expected[%#v]", aud, scopes, matchedJws)
		proxywasm.SendHttpResponse(403, nil, []byte("Forbidden: scope(s) not allowed"), -1)
		return false
	}
	actionValue, _ := proxywasm.GetHttpRequestHeader(ctx.plugin.actionHeader)
	resourceValue, _ := proxywasm.GetHttpRequestHeader(ctx.plugin.resourceHeader)
	action := strings.ToLower(actionValue)
	resource := strings.ToLower(resourceValue)
	proxywasm.LogDebugf("attempting to check request header: %s[%s], %s[%s]", ctx.plugin.actionHeader, action, ctx.plugin.resourceHeader, resource)
	if !authorizePolicyAccess(aud, action, resource, assertions) {
		proxywasm.LogWarnf("forbidden: request denied by policy: action[%s], resource[%s], assertions[%#v]", action, resource, assertions)
		proxywasm.SendHttpResponse(403, nil, []byte("Forbidden: access denied by policy"), -1)
		return false
	}
	return true
}
