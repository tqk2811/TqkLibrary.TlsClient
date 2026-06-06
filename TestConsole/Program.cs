using TqkLibrary.TlsClient;

// Phase 3c demo: a normal HttpClient whose terminal handler impersonates Chrome's TLS AND HTTP/2.
// The handler negotiates h2 via ALPN and speaks Chrome-fingerprinted HTTP/2 automatically.
using var handler = new TlsImpersonateHandler
{
    Profile = "chrome",
    InsecureSkipVerify = true, // the native (Go) verifier does not do AIA intermediate chasing
};
using var http = new HttpClient(handler);
http.DefaultRequestHeaders.TryAddWithoutValidation(
    "user-agent",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");

using var res = await http.GetAsync("https://www.google.com/");
Console.WriteLine($"HTTP/{res.Version} {(int)res.StatusCode} {res.ReasonPhrase}");
Console.WriteLine($"Content-Type: {res.Content.Headers.ContentType}");
string body = await res.Content.ReadAsStringAsync();
Console.WriteLine($"body: {body.Length} chars");
Console.WriteLine(body.Substring(0, Math.Min(120, body.Length)));
