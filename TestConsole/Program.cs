using TqkLibrary.TlsClient;
using TqkLibrary.TlsClient.Profiles;

using var http = TlsProfile.Chrome().CreateHttpClient();
http.DefaultRequestHeaders.TryAddWithoutValidation("user-agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/124.0.0.0 Safari/537.36");
http.DefaultRequestHeaders.TryAddWithoutValidation("accept-encoding", "gzip, deflate, br");

foreach (var (path, marker) in new[] { ("/httpbin/gzip", "gzipped"), ("/httpbin/brotli", "brotli"), ("/httpbin/deflate", "deflated") })
{
    using var res = await http.GetAsync("https://nghttp2.org" + path);
    string body = await res.Content.ReadAsStringAsync();
    Console.WriteLine($"{path,-18}: HTTP {(int)res.StatusCode}  decodedOk={body.Contains(marker)}  len={body.Length}");
}
