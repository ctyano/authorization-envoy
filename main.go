package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/tidwall/gjson"

	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"
)

type Assertion struct {
	Effect   string `json:effect`
	Role     string `json:"role"`
	Action   string `json:action`
	Resource string `json:resource`
}

type Policy struct {
	Name       string      `json:"name"`
	Assertions []Assertion `json:"assertions"`
}

type PolicyData struct {
	Domain   string   `json:"domain"`
	Policies []Policy `json:"policies"`
}

type JwsPolicyPayload struct {
	PolicyData PolicyData `json:"policyData"`
}

type Constraint struct {
	Domain string
	Role   string
}

// vmContext implements types.VMContext.
type vmContext struct {
	// Embed the default VM context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultVMContext
}

// pluginContext implements types.PluginContext.
type pluginContext struct {
	// Embed the default plugin context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultPluginContext

	constraints []Constraint
	policy      *JwsPolicyPayload
	lastUpdated int64 // UnixNano (optional)

	policyCluster   string
	policyPath      string
	policyAuthority string
	actionHeader    string
	resourceHeader  string
	policyRefresh   uint32 // in milliseconds

}

type httpContext struct {
	types.DefaultHttpContext
	plugin    *pluginContext
	contextID uint32
}

func main() {}

func init() {
	proxywasm.SetVMContext(&vmContext{})
}

// NewPluginContext implements types.VMContext.
func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &pluginContext{}
}

// Fetch policy on startup and start timer for periodic refresh.
func (p *pluginContext) OnVMStart(vmConfigurationSize int) types.OnVMStartStatus {
	return types.OnVMStartStatusOK
}

// NewHttpContext implements types.PluginContext.
func (p *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	return &httpContext{
		plugin:    p,
		contextID: contextID,
	}
}

func (p *pluginContext) OnTick() {
	proxywasm.LogInfo("Periodic policy refresh...")
	p.fetchPolicy()
}

// OnPluginStart implements types.PluginContext.
// Note that this parses the json data by gjson, since TinyGo doesn't support encoding/json.
// You can also try https://github.com/mailru/easyjson, which supports decoding to a struct.
// configuration:
//   "@type": type.googleapis.com/google.protobuf.StringValue
//   value: |
//     {
//       "user_prefix": "<prefix to prepend to the jwt claim to compare with csr subject cn as an athenz user name. e.g. user.>",
//       "claim": "<jwt claim name to extract athenz user name>"
//     }
func (p *pluginContext) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	proxywasm.LogDebug("Loading plugin config")
	data, err := proxywasm.GetPluginConfiguration()
	if data == nil {
		return types.OnPluginStartStatusOK
	}

	if err != nil {
		proxywasm.LogCriticalf("Error reading plugin configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}

	if !gjson.Valid(string(data)) {
		proxywasm.LogCriticalf(`Invalid JSON format in configuration: %s`, string(data))
		return types.OnPluginStartStatusFailed
	}

	// cga stands for coarse grained authorization
	/*
	   "cga": [
	     { "athenz": { "domain": "athenz", "role": "envoy-clients" } }
	   ],
	*/
	cga := gjson.Get(string(data), "cga")
	if cga.Exists() && cga.Type != gjson.Null {
		cga.ForEach(func(_, constraint gjson.Result) bool {
			c := Constraint{
				Domain: constraint.Get("domain").String(),
				Role:   constraint.Get("role").String(),
			}
			p.constraints = append(p.constraints, c)
			return true
		})
		fmt.Printf("Coarse-Grained Authorization Config: %#v\n", p.constraints)
		proxywasm.SetProperty([]string{"mode"}, []byte("cga"))
	}

	// fga stands for fine grained authorization
	/*
	   "fga": {
	     "cluster": "zts",
	     "path": "/zts/v1/domain/sys.auth/policy/signed",
	     "authority": "athenz-zts-server.athenz",
	     "refresh": 30000
	   }
	*/
	fga := gjson.Get(string(data), "fga")
	if fga.Exists() && fga.Type != gjson.Null {
		p.policyCluster = strings.TrimSpace(fga.Get("cluster").String())
		p.policyPath = strings.TrimSpace(fga.Get("path").String())
		p.policyAuthority = strings.TrimSpace(fga.Get("authority").String())
		p.actionHeader = strings.TrimSpace(fga.Get("actionheader").String())
		p.resourceHeader = strings.TrimSpace(fga.Get("resourceheader").String())
		p.policyRefresh = uint32(fga.Get("refresh").Int())
		proxywasm.LogInfof("Fine-Grained Authorization Config: cluster=%s, path=%s, authority=%s, refresh=%d", p.policyCluster, p.policyPath, p.policyAuthority, p.policyRefresh)

		if err := proxywasm.SetTickPeriodMilliSeconds(p.policyRefresh); err != nil {
			proxywasm.LogCriticalf("failed to set tick period: %v", err)
			return types.OnPluginStartStatusFailed
		}
		proxywasm.LogInfof("Set tick period milliseconds: %d", p.policyRefresh)

		proxywasm.LogInfo("Fetching initial policy...")
		p.fetchPolicy()
	}

	return types.OnPluginStartStatusOK
}

// OnHttpRequestHeaders implements types.HttpContext.
func (ctx *httpContext) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	hs, err := proxywasm.GetHttpRequestHeaders()
	if err != nil {
		proxywasm.LogCriticalf("Failed to get request headers: %v", err)
	}
	for _, h := range hs {
		proxywasm.LogInfof("Request header --> %s: %s", h[0], h[1])
	}

	auth, err := proxywasm.GetHttpRequestHeader("authorization")
	if err != nil || !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		proxywasm.LogWarnf("Missing or invalid authorization header")
		proxywasm.SendHttpResponse(401, nil, []byte("Missing or invalid authorization header"), -1)
		proxywasm.SetProperty([]string{"result"}, []byte("failure"))
		return types.ActionPause
	}
	// JWT: not validated, just parsed for name
	// This plugin expects the JWT to be validated with Envoy JWT Filter
	rawJWT := strings.TrimPrefix(strings.TrimPrefix(auth, "bearer "), "Bearer ")

	aud, scopes, err := extractAudAndScopesFromJWT(rawJWT)
	if err != nil {
		proxywasm.LogWarnf("Failed to extract aud/scopes: %v", err)
		proxywasm.SendHttpResponse(401, nil, []byte("Invalid JWT"), -1)
		return types.ActionPause
	}
	//mode, _ := proxywasm.GetProperty([]string{"mode"})
	//if string(mode) == "fga" {
	// Compare audience
	if !strings.EqualFold(aud, ctx.plugin.policy.PolicyData.Domain) {
		proxywasm.LogDebugf("Forbidden: audience mismatch: request[%s], expected[%s]", aud, ctx.plugin.policy.PolicyData.Domain)
		proxywasm.SendHttpResponse(403, nil, []byte("Forbidden: audience mismatch"), -1)
		return types.ActionPause
	}
	// Compare scopes (scope and scp) with all roles in assertions
	var assertions []Assertion
	if assertions = matchedAssertions(aud, scopes, ctx.plugin.policy); assertions == nil {
		proxywasm.LogDebugf("Forbidden: scope(s) not allowed: request[%#v], expected[%#v]", scopes, ctx.plugin.policy)
		proxywasm.SendHttpResponse(403, nil, []byte("Forbidden: scope(s) not allowed"), -1)
		return types.ActionPause
	}
	action, _ := proxywasm.GetHttpRequestHeader(ctx.plugin.actionHeader)
	resource, _ := proxywasm.GetHttpRequestHeader(ctx.plugin.resourceHeader)
	proxywasm.LogDebugf("Attempting to check request header: %s[%s], %s[%s]", ctx.plugin.actionHeader, strings.ToLower(action), ctx.plugin.resourceHeader, strings.ToLower(resource))
	if !authorizeAccess(strings.ToLower(aud), strings.ToLower(action), strings.ToLower(resource), assertions) {
		proxywasm.SetProperty([]string{"result"}, []byte("unauthorized"))
		return types.ActionPause
	}
	//}

	// Save name for later in context
	proxywasm.SetProperty([]string{"result"}, []byte("authorized"))
	proxywasm.LogDebugf("Saved the audience in request_audience property: %s", aud)
	proxywasm.SetProperty([]string{"request_audience"}, []byte(aud))

	return types.ActionContinue
}

// OnHttpResponseHeaders implements types.HttpContext.
func (*httpContext) OnHttpResponseHeaders(_ int, _ bool) types.Action {
	resultBytes, _ := proxywasm.GetProperty([]string{"result"})
	if err := proxywasm.AddHttpResponseHeader("x-authorization-envoy-wasm", string(resultBytes)); err != nil {
		proxywasm.LogCriticalf("Failed to set response constant header: %v", err)
	}
	hs, err := proxywasm.GetHttpResponseHeaders()
	if err != nil {
		proxywasm.LogCriticalf("Failed to get response headers: %v", err)
	}
	for _, h := range hs {
		proxywasm.LogInfof("Response header <-- %s: %s", h[0], h[1])
	}

	return types.ActionContinue
}

// Fetch the JWS policy via POST, as required.
func (p *pluginContext) fetchPolicy() {
	headers := [][2]string{
		{":method", "POST"},
		{":path", p.policyPath},
		{":authority", p.policyAuthority},
		{"content-type", "application/json"},
	}
	reqBody := `{"policyVersions":{"":""}}` // As per your curl command

	proxywasm.LogInfof("Attempting to request policy to cluster[%s], path[%s], authority[%s]", p.policyCluster, p.policyPath, p.policyAuthority)
	proxywasm.DispatchHttpCall(
		p.policyCluster, headers[:], []byte(reqBody), nil, 10000,
		func(numHeaders, bodySize, numTrailers int) {
			body, err := proxywasm.GetHttpCallResponseBody(0, bodySize)
			if err != nil {
				proxywasm.LogCriticalf("Failed to get policy body: %v", err)
				return
			}
			var jws map[string]interface{}
			if err := json.Unmarshal(body, &jws); err != nil {
				proxywasm.LogCriticalf("Failed to parse JWS: %v", err)
				return
			}
			payloadB64, ok := jws["payload"].(string)
			if !ok {
				proxywasm.LogCritical("Policy missing payload")
				return
			}
			payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
			if err != nil {
				proxywasm.LogCriticalf("Failed to decode policy payload: %v", err)
				return
			}
			var policyPayload JwsPolicyPayload
			if err := json.Unmarshal(payloadJSON, &policyPayload); err != nil {
				proxywasm.LogCriticalf("Failed to parse policy payload: %v", err)
				return
			}
			p.policy = &policyPayload
			p.lastUpdated = time.Now().UnixNano()
			proxywasm.LogInfo("Policy loaded/refreshed successfully")
			proxywasm.LogInfof("Policy:\n%#v\n", policyPayload)
		})
}

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
func matchedAssertions(audience string, scopes []string, policy *JwsPolicyPayload) []Assertion {
	if len(scopes) == 0 {
		return nil
	}
	roleSet := make(map[string]Assertion)
	for _, p := range policy.PolicyData.Policies {
		for _, a := range p.Assertions {
			roleSet[a.Role] = a
		}
	}
	var assertions []Assertion
	for _, s := range scopes {
		if _, found := roleSet[audience+":role."+s]; found {
			a := roleSet[audience+":role."+s]
			proxywasm.LogDebugf("assertion matched: request[%s], assertion[%#v]", audience+":role."+s, a)
			assertions = append(assertions, a)
		}
	}
	return assertions
}

// Returns true if the assertions match with the request
func authorizeAccess(audience, action, resource string, assertions []Assertion) bool {
	if len(assertions) == 0 {
		return false
	}
	for _, a := range assertions {
		proxywasm.LogDebugf("checking assertion with request: assertion{action[%s], resource[%s]}, request{action[%s], resource[%s]}", a.Action, a.Resource, action, audience+":"+resource)
		actionMatched, _ := path.Match(a.Action, action)
		resourceMatched, _ := path.Match(a.Resource, audience+":"+resource)
		if actionMatched && resourceMatched {
			proxywasm.LogDebugf("assertion matched with request: action[%s], resource[%s]", action, resource)
			return true
		}
	}
	return false
}
