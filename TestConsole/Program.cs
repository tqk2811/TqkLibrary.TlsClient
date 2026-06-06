using TqkLibrary.TlsClient;
using TqkLibrary.TlsClient.Profiles;
using var http = TlsProfile.Chrome().CreateHttpClient();
http.DefaultRequestHeaders.TryAddWithoutValidation("user-agent","Mozilla/5.0 Chrome/124");
using var res = await http.GetAsync("https://nghttp2.org/httpbin/get");
Console.WriteLine($"HTTP/{res.Version} {(int)res.StatusCode}  len={(await res.Content.ReadAsStringAsync()).Length}");
