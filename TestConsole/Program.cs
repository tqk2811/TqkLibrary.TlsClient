using System.Net.Sockets;
using System.Text;
using TqkLibrary.TlsClient.Native;
using TqkLibrary.TlsClient.Native.Models;

// Phase 1 milestone: raw TcpClient stream -> ImpersonatedTlsStream (Stream in -> Stream out)
// -> raw HTTP/1.1 -> read JSON -> the JA3 the server saw should be Chrome's.
const string host = "tls.browserleaks.com";

using var tcp = new TcpClient();
await tcp.ConnectAsync(host, 443);

await using var tls = new ImpersonatedTlsStream(tcp.GetStream(), ownsInner: false);
await tls.AuthenticateAsClientAsync(new TlsCodecOptions
{
    ServerName = host,
    Profile = "chrome",
    Alpn = new[] { "http/1.1" },
    InsecureSkipVerify = true,
});
Console.WriteLine($"ALPN negotiated: {tls.NegotiatedAlpn}");

string req =
    "GET /json HTTP/1.1\r\n" +
    $"Host: {host}\r\n" +
    "User-Agent: tqktls-phase1\r\n" +
    "Accept: */*\r\n" +
    "Connection: close\r\n\r\n";
await tls.WriteAsync(Encoding.ASCII.GetBytes(req));
await tls.FlushAsync();

using var ms = new MemoryStream();
byte[] buf = new byte[8192];
int n;
while ((n = await tls.ReadAsync(buf)) > 0)
    ms.Write(buf, 0, n);

Console.WriteLine(Encoding.UTF8.GetString(ms.ToArray()));
