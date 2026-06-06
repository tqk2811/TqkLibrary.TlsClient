using TqkLibrary.TlsClient;
using TqkLibrary.TlsClient.Profiles;

// Certificate validation: default verify accepts valid certs and rejects bad ones; a callback can override.
async Task Try(string label, string url, bool insecure = false, Action<TlsImpersonateHandler>? configure = null)
{
    var handler = new TlsImpersonateHandler(TlsProfile.Chrome()) { InsecureSkipVerify = insecure };
    configure?.Invoke(handler);
    using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
    http.DefaultRequestHeaders.TryAddWithoutValidation(
        "user-agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");
    try
    {
        using var res = await http.GetAsync(url);
        Console.WriteLine($"{label,-34}: ACCEPTED  HTTP {(int)res.StatusCode}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"{label,-34}: REJECTED  {(ex.InnerException ?? ex).Message}");
    }
}

await Try("valid (default verify)", "https://cdn.jsdelivr.net/npm/typescript@5.4.5/package.json");
await Try("self-signed (default verify)", "https://self-signed.badssl.com/");
await Try("self-signed (callback accepts)", "https://self-signed.badssl.com/",
    configure: h => h.ServerCertificateValidationCallback = (_, _, _, _) => true);
await Try("wrong-host (default verify)", "https://wrong.host.badssl.com/");
await Try("self-signed (InsecureSkipVerify)", "https://self-signed.badssl.com/", insecure: true);
