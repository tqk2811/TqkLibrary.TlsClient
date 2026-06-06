using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TqkLibrary.TlsClient;
using TqkLibrary.TlsClient.Profiles;

const string ja3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27,29-23-24,0";
string expected = Convert.ToHexString(MD5.HashData(Encoding.ASCII.GetBytes(ja3))).ToLowerInvariant();

var p = TlsProfile.FromJa3(ja3);
p.Alpn = new List<string> { "http/1.1" };
using var http = p.CreateHttpClient();
http.DefaultRequestHeaders.TryAddWithoutValidation("user-agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/124.0.0.0 Safari/537.36");
using var res = await http.GetAsync("https://tls.browserleaks.com/json");
string body = await res.Content.ReadAsStringAsync();
using var doc = JsonDocument.Parse(body);
string got = doc.RootElement.GetProperty("ja3_hash").GetString() ?? "";
Console.WriteLine($"expected ja3_hash = {expected}");
Console.WriteLine($"browserleaks      = {got}");
Console.WriteLine(expected == got ? "OK: JA3 reproduced exactly" : "MISMATCH");
Console.WriteLine($"ja3_text(server)  = {doc.RootElement.GetProperty("ja3_text").GetString()}");
