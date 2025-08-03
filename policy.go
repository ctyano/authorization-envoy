package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
)

// Fetch the JWS policy via POST, as required.
func (p *pluginContext) fetchPolicy() {
	for _, domain := range p.policyDomains {
		path := ReplacePlaceholders(p.policyPath, map[string]string{"domain": domain})
		headers := [][2]string{
			{":method", "POST"},
			{":path", path},
			{":authority", p.policyAuthority},
			{"content-type", "application/json"},
		}
		reqBody := `{"policyVersions":{"":""}}` // As per your curl command

		proxywasm.LogInfof("attempting to request policy to cluster[%s], path[%s], authority[%s]", p.policyCluster, path, p.policyAuthority)
		proxywasm.DispatchHttpCall(
			p.policyCluster, headers[:], []byte(reqBody), nil, 10000,
			func(numHeaders, bodySize, numTrailers int) {
				body, err := proxywasm.GetHttpCallResponseBody(0, bodySize)
				if err != nil {
					proxywasm.LogCriticalf("failed to get policy body: %s", err)
					return
				}
				var jws map[string]interface{}
				if err := json.Unmarshal(body, &jws); err != nil {
					proxywasm.LogCriticalf("failed to parse JWS: %s", err)
					return
				}
				payloadB64, ok := jws["payload"].(string)
				if !ok {
					proxywasm.LogCritical("payload missing in JWS policy")
					return
				}
				payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
				if err != nil {
					proxywasm.LogCriticalf("failed to decode policy payload: %s", err)
					return
				}
				var policyPayload JwsPolicyPayload
				if err := json.Unmarshal(payloadJSON, &policyPayload); err != nil {
					proxywasm.LogCriticalf("failed to parse policy payload: %s", err)
					return
				}
				p.policy = append(p.policy, &policyPayload)
				p.lastUpdated = time.Now().UnixNano()
				proxywasm.LogInfo("policy loaded/refreshed successfully")
				proxywasm.LogInfof("policy:\n%#v", policyPayload)
			})
	}
}

func ReplacePlaceholders(s string, values map[string]string) string {
	for k, v := range values {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}
