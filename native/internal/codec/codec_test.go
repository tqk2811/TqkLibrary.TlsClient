package codec

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestPeetJA3 is the Phase 0 milestone: dial tls.peet.ws with a Chrome ClientHello
// over a REAL TCP conn (no cgo), do an HTTP/1.1 request, and print the JA3/JA4/peetprint
// the server observed so we can confirm it matches Chrome.
func TestPeetJA3(t *testing.T) {
	const host = "tls.browserleaks.com"
	raw, err := net.DialTimeout("tcp", host+":443", 15*time.Second)
	if err != nil {
		t.Skipf("network unavailable: %v", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(20 * time.Second))

	opts := &Options{
		ServerName:         host,
		Profile:            "chrome",
		Alpn:               []string{"http/1.1"}, // force http/1.1 so we can speak raw HTTP/1.1 here
		InsecureSkipVerify: true,                 // this test only checks the ClientHello fingerprint
	}
	uconn, err := DialTLS(raw, opts)
	if err != nil {
		t.Fatalf("DialTLS: %v", err)
	}
	t.Logf("negotiated ALPN: %q", uconn.ConnectionState().NegotiatedProtocol)

	req := "GET /json HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: tqktls-phase0\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := uconn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(uconn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	var sb strings.Builder
	_, _ = io.Copy(&sb, resp.Body)
	t.Logf("HTTP %d\n%s", resp.StatusCode, sb.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d", resp.StatusCode)
	}
}
