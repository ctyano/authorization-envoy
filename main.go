package main

import (
	"fmt"
	"strings"

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

	coarseGrainedAuthorization bool
	constraints                []Constraint

	fineGrainedAuthorization bool
	policy                   map[string]*JwsPolicyPayload
	lastUpdated              int64 // UnixNano (optional)
	policyCluster            string
	policyPath               string
	policyDomains            []string
	policyAuthority          string
	actionHeader             string
	resourceHeader           string
	policyRefresh            uint32 // in milliseconds
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
// Note that this parses the json string by gjson, since TinyGo doesn't support encoding/json.
// You can also try https://github.com/mailru/easyjson, which supports decoding to a struct.
// configuration:
//
//	"@type": type.googleapis.com/google.protobuf.StringValue
//	value: |
//	  {
//	    "user_prefix": "<prefix to prepend to the jwt claim to compare with csr subject cn as an athenz user name. e.g. user.>",
//	    "claim": "<jwt claim name to extract athenz user name>"
//	  }
func (p *pluginContext) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	proxywasm.LogDebug("Loading plugin config")
	rawConfig, err := proxywasm.GetPluginConfiguration()
	if rawConfig == nil {
		return types.OnPluginStartStatusOK
	}

	if err != nil {
		proxywasm.LogCriticalf("error reading plugin configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}

	if !gjson.Valid(string(rawConfig)) {
		proxywasm.LogCriticalf(`invalid JSON format in configuration: %s`, string(rawConfig))
		return types.OnPluginStartStatusFailed
	}

	// cga stands for coarse grained authorization
	/*
	   "cga": { // optional
	     "constraints": [ {"domain": "sys.auth", "role": "admin"}, {"domain": "athenz", "role": "envoy-clients"} ]
	   },
	*/
	constraints := gjson.Get(string(rawConfig), "cga.constraints")
	if constraints.Exists() && constraints.Type != gjson.Null {
		constraints.ForEach(func(_, constraint gjson.Result) bool {
			c := Constraint{
				Domain: constraint.Get("domain").String(),
				Role:   constraint.Get("role").String(),
			}
			p.constraints = append(p.constraints, c)
			return true
		})
		proxywasm.LogInfof("coarse-grained authorization configuration: %#v\n", p.constraints)
		p.coarseGrainedAuthorization = true
	}

	// fga stands for fine grained authorization
	/*
	   "fga": { // optional
	     "cluster": "localhost",
	     "path": "/zts/v1/domain/{{domain}}/policy/signed",
	     "domains": { // optional
	       "static": ["sys.auth", "athenz"]
	     },
	     "authority": "athenz-zts-server.athenz",
	     "actionheader": ":method",
	     "resourceheader": ":path",
	     "refresh": 30000
	   }
	*/
	fga := gjson.Get(string(rawConfig), "fga")
	if fga.Exists() && fga.Type != gjson.Null {
		p.policyCluster = strings.TrimSpace(fga.Get("cluster").String())
		p.policyPath = strings.TrimSpace(fga.Get("path").String())
		fga.Get("domains.static").ForEach(func(_, policyDomain gjson.Result) bool {
			p.policyDomains = append(p.policyDomains, strings.TrimSpace(policyDomain.String()))
			return true
		})
		p.policyAuthority = strings.TrimSpace(fga.Get("authority").String())
		p.actionHeader = strings.TrimSpace(fga.Get("actionheader").String())
		p.resourceHeader = strings.TrimSpace(fga.Get("resourceheader").String())
		p.policyRefresh = uint32(fga.Get("refresh").Int())
		proxywasm.LogInfof("fine-grained authorization configuration: cluster=%s, path=%s, domains=[%q], authority=%s, refresh=%d", p.policyCluster, p.policyPath, p.policyDomains, p.policyAuthority, p.policyRefresh)

		if err := proxywasm.SetTickPeriodMilliSeconds(p.policyRefresh); err != nil {
			proxywasm.LogCriticalf("failed to set tick period: %v", err)
			return types.OnPluginStartStatusFailed
		}
		proxywasm.LogInfof("set tick period milliseconds: %d", p.policyRefresh)

		proxywasm.LogInfo("fetching initial policy...")
		p.fetchPolicy()
		p.fineGrainedAuthorization = true
	}

	if !p.coarseGrainedAuthorization && !p.fineGrainedAuthorization {
		proxywasm.LogCriticalf("failed set any authorization config: config[%s]", string(rawConfig))
		return types.OnPluginStartStatusFailed
	}

	return types.OnPluginStartStatusOK
}

// OnHttpRequestHeaders implements types.HttpContext.
func (ctx *httpContext) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	auth, err := proxywasm.GetHttpRequestHeader("authorization")
	if err != nil || !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		proxywasm.LogWarnf("missing or invalid authorization header")
		proxywasm.SendHttpResponse(401, nil, []byte("Invalid authorization header"), -1)
		return types.ActionPause
	}
	// Trim the first 7 characters and other spaces
	rawJWT := strings.TrimSpace(auth[8:])

	// JWT: not validated, just parsed for name
	// This plugin expects the JWT to be validated with Envoy JWT Filter
	aud, scopes, err := extractAudAndScopesFromJWT(rawJWT)
	if err != nil {
		proxywasm.LogWarnf("failed to extract aud/scopes: %v", err)
		proxywasm.SendHttpResponse(401, nil, []byte("Invalid JWT"), -1)
		return types.ActionPause
	}

	cgaEnabled := ctx.plugin.coarseGrainedAuthorization
	fgaEnabled := ctx.plugin.fineGrainedAuthorization

	if !cgaEnabled && !fgaEnabled {
		proxywasm.SendHttpResponse(503, nil, []byte("Service Unavailable: coarse-grained authorization and fine-grained authorization are both disabled."), -1)
		return types.ActionPause
	}

	var cgaerr, fgaerr error

	if cgaEnabled {
		cgaerr = checkCoarseGrainedAuthorization(ctx, aud, scopes)
	}
	if fgaEnabled {
		fgaerr = checkFineGrainedAuthorization(ctx, aud, scopes)
	}

	var forbidden bool
	var logMessage string

	// The request is forbidden if all enabled authorization methods fail.
	// If both CGA and FGA are enabled, this means access is granted if at least one succeeds (OR logic).
	cgaAuthFailed := !cgaEnabled || cgaerr != nil
	fgaAuthFailed := !fgaEnabled || fgaerr != nil
	if cgaAuthFailed && fgaAuthFailed {
		forbidden = true
		var errs []string
		if cgaerr != nil {
			errs = append(errs, fmt.Sprintf("coarse-grained authorization[%s]", cgaerr))
		}
		if fgaerr != nil {
			errs = append(errs, fmt.Sprintf("fine-grained authorization[%s]", fgaerr))
		}
		logMessage = "Forbidden: " + strings.Join(errs, ", ")
	}

	if forbidden {
		proxywasm.LogWarn(logMessage)
		proxywasm.SendHttpResponse(403, nil, []byte("Forbidden"), -1)
		return types.ActionPause
	}

	return types.ActionContinue
}
