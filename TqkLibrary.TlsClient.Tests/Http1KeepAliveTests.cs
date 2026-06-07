using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.TlsClient.Http1;
using Xunit;

namespace TqkLibrary.TlsClient.Tests
{
    public class Http1KeepAliveTests
    {
        [Fact]
        public async Task KeepAlive_ReusesConnection_ForSecondRequest()
        {
            // Two complete responses back-to-back on one connection (the header read of the first over-reads
            // into the second, which keep-alive must hand back for the second request).
            const string raw =
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nAB" +
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nCD";
            var dup = new DuplexTestStream(Encoding.ASCII.GetBytes(raw));
            var owner = new FlagDisposable();
            var conn = new Http1Connection(dup, owner);

            bool? reusable1 = null;
            conn.OnResponseDrained = r => reusable1 = r;
            using (var req1 = new HttpRequestMessage(HttpMethod.Get, "https://example.com/1"))
            using (var resp1 = await conn.SendAsync(req1, CancellationToken.None))
            {
                Assert.Equal("AB", await resp1.Content.ReadAsStringAsync());
            }
            Assert.True(reusable1); // HTTP/1.1 + Content-Length + fully drained → reusable

            bool? reusable2 = null;
            conn.OnResponseDrained = r => reusable2 = r;
            using (var req2 = new HttpRequestMessage(HttpMethod.Get, "https://example.com/2"))
            using (var resp2 = await conn.SendAsync(req2, CancellationToken.None))
            {
                // Proves the over-read leftover was seeded and the read buffer reset for the reused connection.
                Assert.Equal("CD", await resp2.Content.ReadAsStringAsync());
            }
            Assert.True(reusable2);
            Assert.False(owner.Disposed); // never disposed across keep-alive reuse (the pool owns the lifetime)
        }

        [Fact]
        public async Task ConnectionClose_IsNotReusable()
        {
            const string raw = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nAB";
            var dup = new DuplexTestStream(Encoding.ASCII.GetBytes(raw));
            var conn = new Http1Connection(dup, new FlagDisposable());

            bool? reusable = null;
            conn.OnResponseDrained = r => reusable = r;
            using (var req = new HttpRequestMessage(HttpMethod.Get, "https://example.com/"))
            using (var resp = await conn.SendAsync(req, CancellationToken.None))
            {
                Assert.Equal("AB", await resp.Content.ReadAsStringAsync());
            }
            Assert.False(reusable); // server asked to close → not reusable
        }

        [Fact]
        public async Task ReadUntilClose_IsNotReusable()
        {
            // No Content-Length and not chunked → body ends at connection close → cannot be reused.
            const string raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello-body";
            var dup = new DuplexTestStream(Encoding.ASCII.GetBytes(raw));
            var conn = new Http1Connection(dup, new FlagDisposable());

            bool? reusable = null;
            conn.OnResponseDrained = r => reusable = r;
            using (var req = new HttpRequestMessage(HttpMethod.Get, "https://example.com/"))
            using (var resp = await conn.SendAsync(req, CancellationToken.None))
            {
                Assert.Equal("hello-body", await resp.Content.ReadAsStringAsync());
            }
            Assert.False(reusable);
        }
    }
}
