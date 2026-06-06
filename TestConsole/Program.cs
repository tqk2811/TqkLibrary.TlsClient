using TqkLibrary.TlsClient;
using TqkLibrary.TlsClient.Profiles;
var p = TlsProfile.Chrome();
p.Alpn = new System.Collections.Generic.List<string>{ "http/1.1" };
using var http = p.CreateHttpClient();
http.DefaultRequestHeaders.TryAddWithoutValidation("user-agent","Mozilla/5.0 (Windows NT 10.0) Chrome/124.0.0.0 Safari/537.36");
using var res = await http.GetAsync("https://nghttp2.org/httpbin/headers");
Console.WriteLine($"HTTP/{res.Version} {(int)res.StatusCode}");
Console.WriteLine(await res.Content.ReadAsStringAsync());
