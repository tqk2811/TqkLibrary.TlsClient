using TqkLibrary.TlsClient;
using TqkLibrary.TlsClient.Profiles;
using TqkLibrary.TlsClient.Proxy;
using TqkLibrary.Proxy.ProxySources;

using var handler = new TlsImpersonateHandler(TlsProfile.Chrome());
handler.UseProxySource(new LocalProxySource()); // direct TCP via IProxySource (drop-in for a real SOCKS/HTTP proxy)
using var http = new HttpClient(handler);
http.DefaultRequestHeaders.TryAddWithoutValidation("user-agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/124.0.0.0 Safari/537.36");
using var res = await http.GetAsync("https://nghttp2.org/httpbin/get");
Console.WriteLine($"HTTP/{res.Version} {(int)res.StatusCode} via IProxySource(LocalProxySource)");
Console.WriteLine((int)res.StatusCode == 200 ? "OK: transport routed through IProxySource" : "FAIL");
