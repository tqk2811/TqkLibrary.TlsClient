using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using TqkLibrary.TlsClient;
using TqkLibrary.TlsClient.Profiles;
using Xunit;

namespace TqkLibrary.TlsClient.Tests
{
    /// <summary>
    /// End-to-end requests through the impersonating stack against a live httpbin service (nghttp2.org/httpbin,
    /// an httpbin deployment that negotiates HTTP/2). These need network access and the native tqktls codec, so
    /// they're tagged Integration: run all tests with <c>dotnet test</c>, or skip these with
    /// <c>dotnet test --filter Category!=Integration</c>.
    /// </summary>
    [Trait("Category", "Integration")]
    public class HttpBinIntegrationTests
    {
        // Swap to https://httpbin.org or https://httpbingo.org if you prefer; all speak the same httpbin API.
        // nghttp2.org/httpbin is used here because it reliably negotiates HTTP/2.
        private const string BaseUrl = "https://nghttp2.org/httpbin";

        private static HttpClient NewClient(TlsImpersonateHandler handler)
            => new(handler) { Timeout = TimeSpan.FromSeconds(30) };

        private static TlsImpersonateHandler NewHandler(params string[] alpn)
        {
            TlsProfile profile = TlsProfile.Chrome();
            if (alpn.Length > 0) profile.Alpn = alpn.ToList();
            return new TlsImpersonateHandler(profile);
        }

        [Fact]
        public async Task Get_OverHttp2_ReturnsOk()
        {
            using var handler = NewHandler();
            using HttpClient http = NewClient(handler);

            using HttpResponseMessage res = await http.GetAsync(BaseUrl + "/get");
            string body = await res.Content.ReadAsStringAsync();

            Assert.Equal(HttpStatusCode.OK, res.StatusCode);
            Assert.Equal(HttpVersion.Version20, res.Version);       // ALPN negotiated h2
            Assert.Contains("/httpbin/get", body);                  // /get echoes the request url
        }

        [Fact]
        public async Task Get_EchoesCustomUserAgent()
        {
            const string ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36";
            using var handler = NewHandler();
            using HttpClient http = NewClient(handler);
            http.DefaultRequestHeaders.TryAddWithoutValidation("user-agent", ua);

            using HttpResponseMessage res = await http.GetAsync(BaseUrl + "/user-agent");
            string body = await res.Content.ReadAsStringAsync();

            Assert.Equal(HttpStatusCode.OK, res.StatusCode);
            Assert.Contains(ua, body); // server reflects the User-Agent we sent
        }

        [Fact]
        public async Task Post_EchoesJsonBody()
        {
            using var handler = NewHandler();
            using HttpClient http = NewClient(handler);
            var content = new StringContent("{\"hello\":\"world\"}", Encoding.UTF8, "application/json");

            using HttpResponseMessage res = await http.PostAsync(BaseUrl + "/post", content);
            string body = await res.Content.ReadAsStringAsync();

            Assert.Equal(HttpStatusCode.OK, res.StatusCode);
            Assert.Contains("hello", body);
            Assert.Contains("world", body);
        }

        [Fact]
        public async Task Status_ReturnsRequestedCode()
        {
            using var handler = NewHandler();
            using HttpClient http = NewClient(handler);

            using HttpResponseMessage res = await http.GetAsync(BaseUrl + "/status/418");

            Assert.Equal(418, (int)res.StatusCode);
        }

        [Fact]
        public async Task Gzip_IsAutomaticallyDecompressed()
        {
            using var handler = NewHandler();
            using HttpClient http = NewClient(handler);
            http.DefaultRequestHeaders.TryAddWithoutValidation("accept-encoding", "gzip, deflate, br");

            using HttpResponseMessage res = await http.GetAsync(BaseUrl + "/gzip");
            string body = await res.Content.ReadAsStringAsync();

            Assert.Equal(HttpStatusCode.OK, res.StatusCode);
            Assert.Contains("\"gzipped\"", body); // decoded JSON payload (auto-decompressed)
        }

        [Fact]
        public async Task Http2_MultiplexesConcurrentRequestsOverOneConnection()
        {
            using var handler = NewHandler(); // h2,http/1.1
            using HttpClient http = NewClient(handler);

            // Fire several requests at once; a multiplexed h2 client serves them all on ONE connection.
            HttpResponseMessage[] responses = await Task.WhenAll(
                Enumerable.Range(0, 6).Select(_ => http.GetAsync(BaseUrl + "/get")));

            try
            {
                Assert.All(responses, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
                Assert.All(responses, r => Assert.Equal(HttpVersion.Version20, r.Version));
                Assert.Equal(1, handler.ConnectionsCreated); // multiplexed, not 6 separate connections
            }
            finally
            {
                foreach (var r in responses) r.Dispose();
            }
        }

        [Fact]
        public async Task Http1_ForcedAlpn_RequestsSucceed()
        {
            // Offer only http/1.1 in the ClientHello so the server negotiates HTTP/1.1 over the impersonated TLS.
            // (Keep-alive *reuse* is covered deterministically by Http1KeepAliveTests; this server sends
            // "Connection: close", so it legitimately can't be reused here.)
            using var handler = NewHandler("http/1.1");
            using HttpClient http = NewClient(handler);

            for (int i = 0; i < 2; i++)
            {
                using HttpResponseMessage res = await http.GetAsync(BaseUrl + "/get");
                string body = await res.Content.ReadAsStringAsync();
                Assert.Equal(HttpStatusCode.OK, res.StatusCode);
                Assert.Equal(HttpVersion.Version11, res.Version);
                Assert.Contains("/httpbin/get", body);
            }
        }
    }
}
