package codec

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestPresetByName(t *testing.T) {
	if _, ok := presetByName("chrome"); !ok {
		t.Fatal(`"chrome" should resolve to a preset`)
	}
	if _, ok := presetByName("chrome_120"); !ok {
		t.Fatal(`"chrome_120" should resolve to a preset`)
	}
	if _, ok := presetByName("does-not-exist"); ok {
		t.Fatal("unknown profile must not resolve")
	}
}

func TestBuildSpec_NoSource(t *testing.T) {
	if _, err := buildSpec(&Options{}); err == nil {
		t.Fatal("expected error when no fingerprint source is set")
	}
}

func TestBuildSpec_Ja3(t *testing.T) {
	ja3 := "771,4865-4866-4867-49195-49199,0-23-65281-10-11-35-16-5-13-51-43-45,29-23-24,0"
	spec, err := buildSpec(&Options{Ja3: ja3})
	if err != nil {
		t.Fatalf("buildSpec(ja3): %v", err)
	}
	if len(spec.CipherSuites) != 5 {
		t.Fatalf("expected 5 cipher suites, got %d", len(spec.CipherSuites))
	}
	if len(spec.Extensions) == 0 {
		t.Fatal("expected extensions from ja3")
	}
}

func TestJa3_InvalidFieldCount(t *testing.T) {
	if _, err := buildSpec(&Options{Ja3: "771,4865"}); err == nil {
		t.Fatal("expected an error for a malformed ja3 string")
	}
}

func TestBuildSpec_Preset(t *testing.T) {
	spec, err := buildSpec(&Options{Profile: "chrome"})
	if err != nil {
		t.Fatalf("buildSpec(chrome): %v", err)
	}
	if spec == nil || len(spec.CipherSuites) == 0 {
		t.Fatal("expected a spec with cipher suites")
	}
}

func TestBuildSpec_RawClientHelloInvalidBase64(t *testing.T) {
	if _, err := buildSpec(&Options{RawClientHelloBase64: "!!!not-base64!!!"}); err == nil {
		t.Fatal("expected base64 decode error")
	}
}

func TestOverrideALPN(t *testing.T) {
	spec, err := buildSpec(&Options{Profile: "chrome"})
	if err != nil {
		t.Fatal(err)
	}
	overrideALPN(spec, []string{"http/1.1"})

	found := false
	for _, ext := range spec.Extensions {
		if a, ok := ext.(*utls.ALPNExtension); ok {
			found = true
			if len(a.AlpnProtocols) != 1 || a.AlpnProtocols[0] != "http/1.1" {
				t.Fatalf("ALPN not overridden, got %v", a.AlpnProtocols)
			}
		}
	}
	if !found {
		t.Fatal("no ALPN extension present after override")
	}
}
