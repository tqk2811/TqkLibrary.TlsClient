using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.TlsClient.Http2;
using TqkLibrary.TlsClient.Http2.Hpack;
using TqkLibrary.TlsClient.Http2.Models;
using Xunit;

namespace TqkLibrary.TlsClient.Tests
{
    public class Http2ConnectionTests
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

        // A minimal server response: empty SETTINGS, HEADERS(:status 200), DATA("hi", END_STREAM).
        private static byte[] ServerResponse()
        {
            using var ms = new MemoryStream();
            Write(ms, Frame(0x4, 0x0, 0, Array.Empty<byte>()));
            Write(ms, Frame(0x1, 0x4, 1, new byte[] { 0x88 }));               // :status 200 (static index 8)
            Write(ms, Frame(0x0, 0x1, 1, Encoding.ASCII.GetBytes("hi")));
            return ms.ToArray();
            static void Write(Stream s, byte[] b) => s.Write(b, 0, b.Length);
        }

        [Fact]
        public async Task EmitsChromeFingerprint_AndParsesResponse()
        {
            var dup = new DuplexTestStream(ServerResponse());
            var conn = new Http2Connection(dup, Http2FingerprintConfig.Chrome());
            using var req = new HttpRequestMessage(HttpMethod.Get, "https://example.com/p");

            using var res = await conn.SendAsync(req, CancellationToken.None);

            Assert.Equal(HttpStatusCode.OK, res.StatusCode);
            Assert.Equal(HttpVersion.Version20, res.Version);
            Assert.Equal("hi", await res.Content.ReadAsStringAsync());

            byte[] sent = dup.Written.ToArray();
            Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(sent, 0, 24));

            List<(byte Type, byte Flags, int StreamId, byte[] Payload)> frames = ParseFrames(sent, 24);

            // Client SETTINGS (flags 0) must match the Chrome akamai settings, in order.
            var settings = frames.First(f => f.Type == 0x4 && f.Flags == 0);
            Assert.Equal("1:65536,2:0,4:6291456,6:262144", FormatSettings(settings.Payload));

            // Connection WINDOW_UPDATE of Chrome's 15663105.
            var windowUpdate = frames.First(f => f.Type == 0x8);
            Assert.Equal(0, windowUpdate.StreamId);
            Assert.Equal(15663105u, BeUInt32(windowUpdate.Payload, 0));

            // HEADERS on stream 1, END_HEADERS|END_STREAM, with Chrome pseudo-header order m,a,s,p.
            var headers = frames.First(f => f.Type == 0x1);
            Assert.Equal(1, headers.StreamId);
            Assert.Equal(0x5, headers.Flags);
            var decoded = new HpackDecoder().Decode(headers.Payload);
            Assert.Equal(new[] { ":method", ":authority", ":scheme", ":path" }, decoded.Take(4).Select(h => h.Key).ToArray());
            Assert.Equal("GET", decoded[0].Value);
            Assert.Equal("example.com", decoded[1].Value);
            Assert.Equal("https", decoded[2].Value);
            Assert.Equal("/p", decoded[3].Value);
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

        private static string FormatSettings(byte[] payload)
        {
            var parts = new List<string>();
            for (int i = 0; i + 6 <= payload.Length; i += 6)
            {
                int id = (payload[i] << 8) | payload[i + 1];
                uint value = BeUInt32(payload, i + 2);
                parts.Add($"{id}:{value}");
            }
            return string.Join(",", parts);
        }

        private static uint BeUInt32(byte[] b, int o)
            => ((uint)b[o] << 24) | ((uint)b[o + 1] << 16) | ((uint)b[o + 2] << 8) | b[o + 3];
    }
}
