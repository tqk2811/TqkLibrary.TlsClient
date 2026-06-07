using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.TlsClient.Http2;
using TqkLibrary.TlsClient.Http2.Models;
using Xunit;

namespace TqkLibrary.TlsClient.Tests
{
    public class Http2MultiplexTests
    {
        private static byte[] Frame(byte type, byte flags, int streamId, byte[] payload)
        {
            var f = new byte[9 + payload.Length];
            f[0] = (byte)(payload.Length >> 16); f[1] = (byte)(payload.Length >> 8); f[2] = (byte)payload.Length;
            f[3] = type; f[4] = flags;
            f[5] = (byte)(streamId >> 24); f[6] = (byte)(streamId >> 16); f[7] = (byte)(streamId >> 8); f[8] = (byte)streamId;
            Buffer.BlockCopy(payload, 0, f, 9, payload.Length);
            return f;
        }

        [Fact]
        public async Task MultiplexesConcurrentRequestsOnOneConnection_AndDemuxesOutOfOrder()
        {
            var srv = new ProgrammableDuplexStream();
            using var conn = new Http2Connection(srv, Http2FingerprintConfig.Chrome());
            srv.Feed(Frame(0x4, 0x0, 0, Array.Empty<byte>())); // server SETTINGS

            using var reqA = new HttpRequestMessage(HttpMethod.Get, "https://example.com/a");
            using var reqB = new HttpRequestMessage(HttpMethod.Get, "https://example.com/b");

            Task<HttpResponseMessage> tA = conn.SendAsync(reqA, CancellationToken.None);
            Task<HttpResponseMessage> tB = conn.SendAsync(reqB, CancellationToken.None);

            // Respond only once BOTH client HEADERS are on the wire (both streams registered), to mirror reality.
            await WaitForHeadersFramesAsync(srv, 2, TimeSpan.FromSeconds(5));

            // Out-of-order on purpose: stream 3's DATA arrives before stream 1's.
            srv.Feed(Frame(0x1, 0x4, 1, new byte[] { 0x88 }));                 // stream 1: :status 200
            srv.Feed(Frame(0x1, 0x4, 3, new byte[] { 0x88 }));                 // stream 3: :status 200
            srv.Feed(Frame(0x0, 0x1, 3, Encoding.ASCII.GetBytes("s3")));        // stream 3 body (END_STREAM)
            srv.Feed(Frame(0x0, 0x1, 1, Encoding.ASCII.GetBytes("s1")));        // stream 1 body (END_STREAM)

            HttpResponseMessage[] responses = await Task.WhenAll(tA, tB);
            string bodyA = await responses[0].Content.ReadAsStringAsync();
            string bodyB = await responses[1].Content.ReadAsStringAsync();

            Assert.All(responses, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
            // Bodies were demultiplexed to the right stream despite interleaving.
            Assert.Equal(new[] { "s1", "s3" }, new[] { bodyA, bodyB }.OrderBy(x => x).ToArray());

            // A single connection: one preface, two HEADERS frames on streams 1 and 3.
            byte[] written = srv.WrittenSnapshot();
            Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(written, 0, 24));
            int[] headerStreams = ParseFrames(written, 24).Where(f => f.Type == 0x1).Select(f => f.StreamId).OrderBy(x => x).ToArray();
            Assert.Equal(new[] { 1, 3 }, headerStreams);

            foreach (var r in responses) r.Dispose();
        }

        private static async Task WaitForHeadersFramesAsync(ProgrammableDuplexStream srv, int count, TimeSpan timeout)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            while (sw.Elapsed < timeout)
            {
                byte[] written = srv.WrittenSnapshot();
                if (written.Length >= 24 && ParseFrames(written, 24).Count(f => f.Type == 0x1) >= count) return;
                await Task.Delay(10).ConfigureAwait(false);
            }
            throw new TimeoutException($"Only saw fewer than {count} HEADERS frames within {timeout}.");
        }

        private static List<(byte Type, byte Flags, int StreamId, byte[] Payload)> ParseFrames(byte[] buffer, int offset)
        {
            var frames = new List<(byte, byte, int, byte[])>();
            int pos = offset;
            while (pos + 9 <= buffer.Length)
            {
                int length = (buffer[pos] << 16) | (buffer[pos + 1] << 8) | buffer[pos + 2];
                byte type = buffer[pos + 3];
                byte flags = buffer[pos + 4];
                int streamId = ((buffer[pos + 5] & 0x7f) << 24) | (buffer[pos + 6] << 16) | (buffer[pos + 7] << 8) | buffer[pos + 8];
                pos += 9;
                if (pos + length > buffer.Length) break;
                byte[] payload = buffer.AsSpan(pos, length).ToArray();
                pos += length;
                frames.Add((type, flags, streamId, payload));
            }
            return frames;
        }
    }
}
