module github.com/ctyano/authorization-envoy

// [Required] Go: v1.24+ - This SDK leverages Go 1.24's support for WASI (WebAssembly System Interface) reactors. You can install a suitable version from the Go installation guide.
// https://github.com/WebAssembly/WASI
// https://go.dev/doc/install
go 1.24

require github.com/proxy-wasm/proxy-wasm-go-sdk v0.0.0-20250212164326-ab4161dcf924

require (
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/tidwall/gjson v1.18.0
)

require (
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
)
