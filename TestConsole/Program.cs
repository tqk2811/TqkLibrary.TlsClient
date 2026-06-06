using System.Text;
using TqkLibrary.TlsClient;
using TqkLibrary.TlsClient.Profiles;

using HttpClient http = TlsProfile.Chrome().CreateHttpClient(insecureSkipVerify: true);
http.Timeout = TimeSpan.FromSeconds(60);
http.DefaultRequestHeaders.TryAddWithoutValidation(
    "user-agent",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");

// recv flow control: download a body larger than the 6.29 MB stream window.
using (var res = await http.GetAsync("https://cdn.jsdelivr.net/npm/typescript@5.4.5/lib/typescript.js"))
{
    byte[] d = await res.Content.ReadAsByteArrayAsync();
    Console.WriteLine($"GET  HTTP/{res.Version} {(int)res.StatusCode}  recv={d.Length}");
}

// send flow control: POST a body larger than the default 65535 send window (forces WINDOW_UPDATE waits).
const int n = 150_000;
byte[] payload = Encoding.ASCII.GetBytes(new string('a', n));
using (var req = new HttpRequestMessage(HttpMethod.Post, "https://nghttp2.org/httpbin/post") { Content = new ByteArrayContent(payload) })
using (var res = await http.SendAsync(req))
{
    string echoed = await res.Content.ReadAsStringAsync();
    bool ok = (int)res.StatusCode == 200 && echoed.Contains(n.ToString()); // httpbin echoes Content-Length
    Console.WriteLine($"POST HTTP/{res.Version} {(int)res.StatusCode}  sent={payload.Length} respLen={echoed.Length}");
    Console.WriteLine(ok ? "OK: large body sent under flow control (server received full length)" : "MISMATCH");
}
