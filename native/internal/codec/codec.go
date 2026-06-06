// Package codec contains the pure-Go TLS impersonation logic built on uTLS.
// It is transport-agnostic: callers pass any net.Conn (a real TCP socket in tests,
// or a callback-backed conn from the cgo layer) and receive a handshaked *utls.UConn.
//
// This package has no cgo dependency, so it can be unit-tested with `go test`
// without a C compiler.
package codec

import (
	"encoding/base64"
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"
)

// Options describes how to impersonate the TLS ClientHello.
// Exactly one fingerprint source is used, in priority order:
// RawClientHelloBase64 (captured from a proxy) > Profile (named preset) > Ja3.
type Options struct {
	ServerName           string   `json:"serverName"`           // SNI
	Profile              string   `json:"profile"`              // named preset, e.g. "chrome", "chrome_120"
	Ja3                  string   `json:"ja3"`                  // JA3 string (not implemented yet)
	RawClientHelloBase64 string   `json:"rawClientHelloBase64"` // full captured TLS ClientHello record, base64
	Alpn                 []string `json:"alpn"`                 // override ALPN protocols (e.g. ["h2","http/1.1"])
	InsecureSkipVerify   bool     `json:"insecureSkipVerify"`
}

// DialTLS layers an impersonated TLS client over transport and completes the handshake.
// transport carries ciphertext; the returned *utls.UConn carries plaintext.
func DialTLS(transport net.Conn, opts *Options) (*utls.UConn, error) {
	spec, err := buildSpec(opts)
	if err != nil {
		return nil, err
	}
	if len(opts.Alpn) > 0 {
		overrideALPN(spec, opts.Alpn)
	}

	config := &utls.Config{
		ServerName:         opts.ServerName,
		InsecureSkipVerify: opts.InsecureSkipVerify,
	}
	uconn := utls.UClient(transport, config, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("apply preset: %w", err)
	}
	if err := uconn.Handshake(); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	return uconn, nil
}

// buildSpec turns Options into a ClientHelloSpec (the "shape" of the ClientHello).
// The handshake regenerates ephemeral key shares / randoms, so this is a template, not a replay.
func buildSpec(opts *Options) (*utls.ClientHelloSpec, error) {
	switch {
	case opts.RawClientHelloBase64 != "":
		raw, err := base64.StdEncoding.DecodeString(opts.RawClientHelloBase64)
		if err != nil {
			return nil, fmt.Errorf("decode rawClientHelloBase64: %w", err)
		}
		f := &utls.Fingerprinter{AllowBluntMimicry: true}
		spec, err := f.FingerprintClientHello(raw)
		if err != nil {
			return nil, fmt.Errorf("fingerprint client hello: %w", err)
		}
		return spec, nil

	case opts.Profile != "":
		id, ok := presetByName(opts.Profile)
		if !ok {
			return nil, fmt.Errorf("unknown profile %q", opts.Profile)
		}
		spec, err := utls.UTLSIdToSpec(id)
		if err != nil {
			return nil, fmt.Errorf("preset %q: %w", opts.Profile, err)
		}
		return &spec, nil

	case opts.Ja3 != "":
		return nil, fmt.Errorf("ja3 mode not implemented yet")
	}
	return nil, fmt.Errorf("no fingerprint source: set rawClientHelloBase64, profile or ja3")
}

// overrideALPN replaces (or appends) the ALPN extension's protocol list.
// Note: JA3 ignores ALPN contents, JA4 encodes only first/last ALPN value.
func overrideALPN(spec *utls.ClientHelloSpec, alpn []string) {
	for _, ext := range spec.Extensions {
		if a, ok := ext.(*utls.ALPNExtension); ok {
			a.AlpnProtocols = alpn
			return
		}
	}
	spec.Extensions = append(spec.Extensions, &utls.ALPNExtension{AlpnProtocols: alpn})
}

// presetByName maps a friendly profile name to a built-in uTLS ClientHelloID.
// Primary workflow is RawClientHelloBase64 (user-captured); presets are a convenience fallback.
func presetByName(name string) (utls.ClientHelloID, bool) {
	switch name {
	case "chrome", "chrome_latest":
		return utls.HelloChrome_Auto, true
	case "chrome_120":
		return utls.HelloChrome_120, true
	case "firefox", "firefox_latest":
		return utls.HelloFirefox_Auto, true
	case "safari", "safari_latest":
		return utls.HelloSafari_Auto, true
	case "ios", "ios_latest":
		return utls.HelloIOS_Auto, true
	case "edge", "edge_latest":
		return utls.HelloEdge_Auto, true
	}
	return utls.ClientHelloID{}, false
}
