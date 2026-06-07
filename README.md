# TqkLibrary.TlsClient

An `HttpClient` that impersonates a browser's **TLS (JA3/JA4)** and **HTTP/2 (Akamai)** fingerprint.

- TLS ClientHello shaping is done by a small native codec built on
  [uTLS](https://github.com/refraction-networking/utls); the managed side speaks HTTP/1.1 and a
  Chrome-fingerprinted HTTP/2 over the resulting stream.
- The fingerprint is **data**: use a named preset, a JA3 string, or a **captured ClientHello**
  (sniff it from your own proxy and replay its shape).
- Bring your own transport/proxy by returning a `Stream`.
- HTTP/2 requests are **multiplexed** over one shared connection per host (like a real browser);
  HTTP/1.1 connections are **kept alive** and pooled.

## Usage

```csharp
using TqkLibrary.TlsClient;
using TqkLibrary.TlsClient.Profiles;

// Chrome preset (or TlsProfile.FromCapturedClientHello(bytes) captured from your proxy).
using HttpClient http = TlsProfile.Chrome().CreateHttpClient();
using var res = await http.GetAsync("https://example.com/");
```

The core primitive is `ImpersonatedTlsStream` — raw `Stream` in (TCP/proxy), TLS plaintext
`Stream` out, just like `SslStream`:

```csharp
using TqkLibrary.TlsClient.Native;
using TqkLibrary.TlsClient.Native.Models;

var tcp = new TcpClient();
await tcp.ConnectAsync("example.com", 443);
var tls = new ImpersonatedTlsStream(tcp.GetStream());
await tls.AuthenticateAsClientAsync(new TlsCodecOptions
{
    ServerName = "example.com",
    Profile = "chrome",
    Alpn = new[] { "h2", "http/1.1" },
});
// tls is now a plaintext stream
```

Compose with your own `DelegatingHandler` pipeline (redirect/cookie handlers) by passing a
`pipeline` to `CreateHttpClient`, or by wrapping `new TlsImpersonateHandler(profile)` yourself.

### Capture a real browser from your proxy

If your proxy reads the raw TCP stream, turn the **pre-encryption** ClientHello (the cleartext
client→server bytes) straight into a profile:

```csharp
using TqkLibrary.TlsClient.Capture;
using TqkLibrary.TlsClient.Profiles;

// rawClientBytes = the first bytes the real browser sent (before TLS is established)
TlsProfile profile = TlsProfile.FromCapturedHandshake(rawClientBytes); // extracts the ClientHello + its ALPN

// or sniff it inline while relaying, then read CapturedClientHello:
var tee = new ClientHelloCaptureStream(clientStream);
```

Only the TLS handshake is cleartext here. Capture the HTTP/2 (Akamai) fingerprint from the decrypted
side and load it with `Http2FingerprintConfig.FromAkamai("1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p")`.

## Building the native library

The native `tqktls` codec is built with Go + [zig](https://ziglang.org) (used as the cgo C compiler):

```powershell
.\native\build.ps1     # -> TqkLibrary.TlsClient/runtimes/win-x64/native/tqktls.dll
.\BuildPush.ps1        # builds native + packs the NuGet package
```

## Notes

- Native RIDs `win-x64`, `linux-x64`, `linux-arm64` cross-compile from any host with Go + zig
  (`native\build.ps1 -Rids win-x64,linux-x64,linux-arm64`). `osx-x64`/`osx-arm64` must be built on a
  Mac (they link Apple frameworks that zig can't supply on its own).
- Certificates are validated on the .NET side (AIA-aware `X509Chain` + hostname check); use
  `InsecureSkipVerify` or `ServerCertificateValidationCallback` to customize.
- HTTP/2 multiplexing (shared per-host connection), HTTP/1.1 keep-alive pooling, transparent
  gzip/deflate/br decompression, flow control and request cancellation are built in. Plug a proxy with
  `TqkLibrary.TlsClient.Proxy` (`handler.UseProxySource(...)`).

MIT licensed.
