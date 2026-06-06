using TqkLibrary.TlsClient;
using TqkLibrary.TlsClient.Profiles;

// Phase 4 demo: one-liner impersonating HttpClient from a profile.
// (Capture from your proxy with TlsProfile.FromCapturedClientHello(bytes) instead of the "chrome" preset.)
using HttpClient http = TlsProfile.Chrome().CreateHttpClient(insecureSkipVerify: true);
http.DefaultRequestHeaders.TryAddWithoutValidation(
    "user-agent",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");

using HttpResponseMessage res = await http.GetAsync("https://www.google.com/");
Console.WriteLine($"HTTP/{res.Version} {(int)res.StatusCode} {res.ReasonPhrase}");
Console.WriteLine($"Content-Type: {res.Content.Headers.ContentType}");
string body = await res.Content.ReadAsStringAsync();
Console.WriteLine($"body: {body.Length} chars");
