using TqkLibrary.TlsClient;
using TqkLibrary.TlsClient.Profiles;

using var handler = new TlsImpersonateHandler(TlsProfile.Chrome());
using var http = new HttpClient(handler);
http.DefaultRequestHeaders.TryAddWithoutValidation(
    "user-agent",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");

// Three sequential requests to the same host should reuse one pooled h2 connection.
for (int i = 0; i < 3; i++)
{
    using var res = await http.GetAsync("https://nghttp2.org/httpbin/get");
    string body = await res.Content.ReadAsStringAsync();
    Console.WriteLine($"GET {i}: HTTP/{res.Version} {(int)res.StatusCode}  len={body.Length}  connectionsCreated={handler.ConnectionsCreated}");
}

Console.WriteLine(handler.ConnectionsCreated == 1
    ? "OK: 3 sequential requests reused one connection"
    : $"created {handler.ConnectionsCreated} connections");
