using System.Diagnostics;
using System.Text;
using TqkLibrary.TlsClient;
using TqkLibrary.TlsClient.Profiles;

using HttpClient http = TlsProfile.Chrome().CreateHttpClient();
http.DefaultRequestHeaders.TryAddWithoutValidation(
    "user-agent",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");

// Streaming: read a >window body incrementally (ResponseHeadersRead so the body streams, not buffers).
using (var res = await http.GetAsync("https://cdn.jsdelivr.net/npm/typescript@5.4.5/lib/typescript.js", HttpCompletionOption.ResponseHeadersRead))
{
    await using var s = await res.Content.ReadAsStreamAsync();
    long total = 0;
    byte[] buf = new byte[65536];
    int n;
    while ((n = await s.ReadAsync(buf)) > 0) total += n;
    Console.WriteLine($"GET (stream) HTTP/{res.Version} {(int)res.StatusCode}  streamed={total}");
}

// Send flow control: POST a body larger than the 65535 window.
byte[] payload = Encoding.ASCII.GetBytes(new string('a', 150_000));
using (var req = new HttpRequestMessage(HttpMethod.Post, "https://nghttp2.org/httpbin/post") { Content = new ByteArrayContent(payload) })
using (var res = await http.SendAsync(req))
{
    string body = await res.Content.ReadAsStringAsync();
    Console.WriteLine($"POST         HTTP/{res.Version} {(int)res.StatusCode}  serverSawFullLength={body.Contains("150000")}");
}

// Cancellation: 5s delay cancelled at 2s.
using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
var sw = Stopwatch.StartNew();
try
{
    using var res = await http.GetAsync("https://nghttp2.org/httpbin/delay/5", cts.Token);
    Console.WriteLine("cancel       UNEXPECTED completion");
}
catch (Exception ex)
{
    sw.Stop();
    Console.WriteLine($"cancel       {sw.ElapsedMilliseconds} ms ({ex.GetType().Name})");
}
