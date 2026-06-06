package codec

import (
	"fmt"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// ja3ToSpec turns a JA3 string ("version,ciphers,extensions,curves,pointFormats") into a ClientHelloSpec.
// JA3 is lossy (it omits e.g. signature algorithms, key-share groups and supported-versions content), so
// sensible browser-like defaults are filled in for content JA3 does not encode. GREASE is not represented
// in JA3 and is therefore not reproduced (which is fine for JA3 matching).
func ja3ToSpec(ja3 string) (*utls.ClientHelloSpec, error) {
	parts := strings.Split(ja3, ",")
	if len(parts) != 5 {
		return nil, fmt.Errorf("invalid ja3: expected 5 comma-separated fields, got %d", len(parts))
	}

	ciphers, err := parseUint16List(parts[1])
	if err != nil {
		return nil, fmt.Errorf("ja3 ciphers: %w", err)
	}
	extIDs, err := parseUint16List(parts[2])
	if err != nil {
		return nil, fmt.Errorf("ja3 extensions: %w", err)
	}
	curveIDs, err := parseUint16List(parts[3])
	if err != nil {
		return nil, fmt.Errorf("ja3 curves: %w", err)
	}
	points, err := parseUint8List(parts[4])
	if err != nil {
		return nil, fmt.Errorf("ja3 point formats: %w", err)
	}

	curves := make([]utls.CurveID, 0, len(curveIDs))
	for _, c := range curveIDs {
		curves = append(curves, utls.CurveID(c))
	}

	spec := &utls.ClientHelloSpec{
		CipherSuites:       ciphers,
		CompressionMethods: []byte{0x00},
		TLSVersMin:         utls.VersionTLS12,
		TLSVersMax:         utls.VersionTLS13,
	}
	for _, id := range extIDs {
		spec.Extensions = append(spec.Extensions, extensionByID(id, curves, points))
	}
	return spec, nil
}

func extensionByID(id uint16, curves []utls.CurveID, points []byte) utls.TLSExtension {
	switch id {
	case 0:
		return &utls.SNIExtension{}
	case 5:
		return &utls.StatusRequestExtension{}
	case 10:
		return &utls.SupportedCurvesExtension{Curves: curves}
	case 11:
		return &utls.SupportedPointsExtension{SupportedPoints: points}
	case 13:
		return &utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: defaultSignatureAlgorithms()}
	case 16:
		return &utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}
	case 18:
		return &utls.SCTExtension{}
	case 21:
		return &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle}
	case 23:
		return &utls.GenericExtension{Id: 23} // extended_master_secret (empty body)
	case 27:
		return &utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{utls.CertCompressionBrotli}}
	case 35:
		return &utls.SessionTicketExtension{}
	case 43:
		return &utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}}
	case 45:
		return &utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}}
	case 51:
		return &utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}}
	case 65281:
		return &utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient}
	default:
		return &utls.GenericExtension{Id: id}
	}
}

func defaultSignatureAlgorithms() []utls.SignatureScheme {
	return []utls.SignatureScheme{
		utls.ECDSAWithP256AndSHA256,
		utls.PSSWithSHA256,
		utls.PKCS1WithSHA256,
		utls.ECDSAWithP384AndSHA384,
		utls.PSSWithSHA384,
		utls.PKCS1WithSHA384,
		utls.PSSWithSHA512,
		utls.PKCS1WithSHA512,
	}
}

func parseUint16List(s string) ([]uint16, error) {
	if s == "" {
		return nil, nil
	}
	tokens := strings.Split(s, "-")
	out := make([]uint16, 0, len(tokens))
	for _, t := range tokens {
		v, err := strconv.ParseUint(t, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid value %q: %w", t, err)
		}
		out = append(out, uint16(v))
	}
	return out, nil
}

func parseUint8List(s string) ([]uint8, error) {
	if s == "" {
		return nil, nil
	}
	tokens := strings.Split(s, "-")
	out := make([]uint8, 0, len(tokens))
	for _, t := range tokens {
		v, err := strconv.ParseUint(t, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid value %q: %w", t, err)
		}
		out = append(out, uint8(v))
	}
	return out, nil
}
