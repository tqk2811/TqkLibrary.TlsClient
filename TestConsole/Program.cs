using System.Net.Sockets;
using System.Text;
using TqkLibrary.TlsClient.Http2;
using TqkLibrary.TlsClient.Http2.Models;
using TqkLibrary.TlsClient.Native;
using TqkLibrary.TlsClient.Native.Models;

// Phase 3a demo: HTTP/2 over the impersonated stream against a lenient h2 server.
const string host = "http2.golang.org";
const string path = "/reqinfo";

using var tcp = new TcpClient();
await tcp.ConnectAsync(host, 443);

await using var tls = new ImpersonatedTlsStream(tcp.GetStream(), ownsInner: false);
await tls.AuthenticateAsClientAsync(new TlsCodecOptions
{
    ServerName = host,
    Profile = "chrome",
    Alpn = new[] { "h2", "http/1.1" },
    InsecureSkipVerify = true,
});
Console.WriteLine($"ALPN negotiated: {tls.NegotiatedAlpn}");

var conn = new Http2Connection(tls, Http2FingerprintConfig.Chrome());
using var req = new HttpRequestMessage(HttpMethod.Get, $"https://{host}{path}");
req.Headers.TryAddWithoutValidation("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");
req.Headers.TryAddWithoutValidation("accept", "*/*");

byte[] body = await conn.SendAsync(req, default);
Console.WriteLine($"body {body.Length} bytes:");
Console.WriteLine(Encoding.UTF8.GetString(body));
