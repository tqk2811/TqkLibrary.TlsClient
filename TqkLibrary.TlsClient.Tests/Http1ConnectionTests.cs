using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.TlsClient.Http1;
using Xunit;

namespace TqkLibrary.TlsClient.Tests
{
    public class Http1ConnectionTests
    {
        [Fact]
        public async Task Get_ParsesResponse_AndRoutesContentHeaders()
        {
            const string raw =
                "HTTP/1.1 200 OK\r\n" +
                "Content-Type: application/json\r\n" +
                "Content-Length: 5\r\n" +
                "Server: test-srv\r\n" +
                "\r\nHELLO";
            var dup = new DuplexTestStream(Encoding.ASCII.GetBytes(raw));
            var conn = new Http1Connection(dup, new FlagDisposable());
            using var req = new HttpRequestMessage(HttpMethod.Get, "https://example.com/path?q=1");

            using var resp = await conn.SendAsync(req, CancellationToken.None);

            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            Assert.Equal("application/json", resp.Content.Headers.ContentType!.MediaType);
            Assert.True(resp.Headers.TryGetValues("Server", out var server));
            Assert.Equal("test-srv", Assert.Single(server));
            Assert.Equal("HELLO", await resp.Content.ReadAsStringAsync());

            string written = Encoding.ASCII.GetString(dup.Written.ToArray());
            Assert.StartsWith("GET /path?q=1 HTTP/1.1\r\n", written);
            Assert.Contains("Host: example.com\r\n", written);
            Assert.DoesNotContain("Connection: close", written);
        }

        [Fact]
        public async Task Post_WritesContentLengthAndBody()
        {
            const string raw = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
            var dup = new DuplexTestStream(Encoding.ASCII.GetBytes(raw));
            var conn = new Http1Connection(dup, new FlagDisposable());
            using var req = new HttpRequestMessage(HttpMethod.Post, "https://example.com/submit")
            {
                Content = new StringContent("{\"a\":1}", Encoding.UTF8, "application/json"),
            };

            using var resp = await conn.SendAsync(req, CancellationToken.None);

            Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
            string written = Encoding.ASCII.GetString(dup.Written.ToArray());
            Assert.Contains("POST /submit HTTP/1.1\r\n", written);
            Assert.Contains("Content-Type: application/json; charset=utf-8\r\n", written);
            Assert.Contains("Content-Length: 7\r\n", written);
            Assert.EndsWith("\r\n\r\n{\"a\":1}", written);
        }

        [Fact]
        public async Task PreservesHeaderOrder_AndRawStructuredValues_AndNoConnectionClose()
        {
            const string raw = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            var dup = new DuplexTestStream(Encoding.ASCII.GetBytes(raw));
            var conn = new Http1Connection(dup, new FlagDisposable());
            using var req = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
            req.Headers.TryAddWithoutValidation("User-Agent", "Mozilla/5.0 (X) Chrome/124");
            req.Headers.TryAddWithoutValidation("Accept", "*/*");
            req.Headers.TryAddWithoutValidation("Accept-Language", "en-US,en;q=0.9");

            using var resp = await conn.SendAsync(req, CancellationToken.None);
            string written = Encoding.ASCII.GetString(dup.Written.ToArray());

            Assert.Contains("User-Agent: Mozilla/5.0 (X) Chrome/124\r\n", written); // one line, not split into product tokens
            Assert.Contains("Accept-Language: en-US,en;q=0.9\r\n", written);          // one line, not split
            Assert.DoesNotContain("Connection: close", written);
            Assert.True(written.IndexOf("User-Agent:", StringComparison.Ordinal) < written.IndexOf("Accept:", StringComparison.Ordinal));
            Assert.True(written.IndexOf("Accept:", StringComparison.Ordinal) < written.IndexOf("Accept-Language:", StringComparison.Ordinal));
        }

        [Fact]
        public async Task NonDefaultPort_IsIncludedInHostHeader()
        {
            const string raw = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            var dup = new DuplexTestStream(Encoding.ASCII.GetBytes(raw));
            var conn = new Http1Connection(dup, new FlagDisposable());
            using var req = new HttpRequestMessage(HttpMethod.Get, "https://example.com:8443/");

            using var resp = await conn.SendAsync(req, CancellationToken.None);

            string written = Encoding.ASCII.GetString(dup.Written.ToArray());
            Assert.Contains("Host: example.com:8443\r\n", written);
        }
    }
}
