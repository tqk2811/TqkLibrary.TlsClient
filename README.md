# TqkLibrary.TlsClient

An `HttpClient` that impersonates a browser's **TLS (JA3/JA4)** and **HTTP/2 (Akamai)** fingerprint.

- TLS ClientHello shaping is done by a small native codec built on
  [uTLS](https://github.com/refraction-networking/utls); the managed side speaks HTTP/1.1 and a
  Chrome-fingerprinted HTTP/2 over the resulting stream.
- The fingerprint is **data**: use a named preset, a JA3 string, or a **captured ClientHello**
  (sniff it from your own proxy and replay its shape).
- Bring your own transport/proxy by returning a `Stream`.

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

## Building the native library

The native `tqktls` codec is built with Go + [zig](https://ziglang.org) (used as the cgo C compiler):

```powershell
.\native\build.ps1     # -> TqkLibrary.TlsClient/runtimes/win-x64/native/tqktls.dll
.\BuildPush.ps1        # builds native + packs the NuGet package
```

## Notes

- Ships `win-x64` native today; other RIDs build with the same Go/zig toolchain (cross-compile).
- The native (Go) certificate verifier does not chase missing AIA intermediates; set
  `InsecureSkipVerify` or ensure servers send complete chains.

MIT licensed.
