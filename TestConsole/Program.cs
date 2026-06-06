using System.Diagnostics;
using TqkLibrary.TlsClient;
using TqkLibrary.TlsClient.Profiles;

using HttpClient http = TlsProfile.Chrome().CreateHttpClient();
http.DefaultRequestHeaders.TryAddWithoutValidation(
    "user-agent",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");

// Normal request still works.
using (var res = await http.GetAsync("https://nghttp2.org/httpbin/get"))
    Console.WriteLine($"normal GET: HTTP/{res.Version} {(int)res.StatusCode}");

// Cancellation: a 5s server delay cancelled after 2s must abort promptly, not hang.
using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
var sw = Stopwatch.StartNew();
try
{
    using var res = await http.GetAsync("https://nghttp2.org/httpbin/delay/5", cts.Token);
    Console.WriteLine($"UNEXPECTED: completed {(int)res.StatusCode} in {sw.ElapsedMilliseconds} ms");
}
catch (Exception ex)
{
    sw.Stop();
    Console.WriteLine($"cancelled after {sw.ElapsedMilliseconds} ms ({ex.GetType().Name})");
    Console.WriteLine(sw.ElapsedMilliseconds < 3500 ? "OK: timed out promptly (did not hang for 5s)" : "FAIL: hung");
}
