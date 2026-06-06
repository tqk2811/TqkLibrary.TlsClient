using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.TlsClient.Http2.Enums;
using TqkLibrary.TlsClient.Http2.Hpack;
using TqkLibrary.TlsClient.Http2.Models;

namespace TqkLibrary.TlsClient.Http2
{
    /// <summary>
    /// A single-request HTTP/2 client over a plaintext stream (e.g. an authenticated ImpersonatedTlsStream).
    /// It emits the connection preface, SETTINGS, connection WINDOW_UPDATE, PRIORITY frames and the request
    /// HEADERS exactly as described by an <see cref="Http2FingerprintConfig"/> (so the Akamai h2 fingerprint
    /// matches the configured browser), then collects the response DATA frames.
    ///
    /// Phase 3a scope: returns the response body bytes; response headers/status are added in Phase 3b
    /// (HPACK decode). One request per connection (no multiplexing/pooling yet).
    /// </summary>
    public sealed class Http2Connection
    {
        private static readonly byte[] Preface = Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        private const int DefaultMaxFrameSize = 16384;

        private readonly Stream _stream;
        private readonly Http2FingerprintConfig _config;
        private readonly byte[] _frameHeader = new byte[9];

        public Http2Connection(Stream stream, Http2FingerprintConfig config)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
            _config = config ?? throw new ArgumentNullException(nameof(config));
        }

        /// <summary>Optional diagnostic sink for received frames (debugging).</summary>
        public Action<string>? Trace { get; set; }

        /// <summary>Sends the request and returns the raw response body. Status/headers come in Phase 3b.</summary>
        public async Task<byte[]> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            const int streamId = 1;

            byte[]? body = request.Content != null
                ? await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false)
                : null;
            bool hasBody = body is { Length: > 0 };

            using var outBuf = new MemoryStream();
            outBuf.Write(Preface, 0, Preface.Length);
            WriteSettingsFrame(outBuf);
            if (_config.ConnectionWindowUpdateIncrement > 0)
                WriteFrame(outBuf, Http2FrameType.WindowUpdate, 0, 0, BeUInt32(_config.ConnectionWindowUpdateIncrement));
            foreach (var p in _config.Priorities)
                WritePriorityFrame(outBuf, p);

            byte[] headerBlock = BuildHeaderBlock(request);
            WriteFrame(outBuf, Http2FrameType.Headers,
                (byte)(Http2FrameFlags.EndHeaders | (hasBody ? 0 : Http2FrameFlags.EndStream)),
                streamId, headerBlock);

            if (hasBody)
                WriteDataFrames(outBuf, streamId, body!);

            byte[] toSend = outBuf.ToArray();
            Trace?.Invoke("send " + Convert.ToHexString(toSend));
            await _stream.WriteAsync(toSend, 0, toSend.Length, cancellationToken).ConfigureAwait(false);
            await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);

            return await ReadResponseBodyAsync(streamId, cancellationToken).ConfigureAwait(false);
        }

        private byte[] BuildHeaderBlock(HttpRequestMessage request)
        {
            Uri uri = request.RequestUri!;
            string authority = uri.IsDefaultPort ? uri.IdnHost : uri.IdnHost + ":" + uri.Port;
            var headers = new List<KeyValuePair<string, string>>();

            foreach (string pseudo in _config.PseudoHeaderOrder)
            {
                string value = pseudo switch
                {
                    ":method" => request.Method.Method,
                    ":authority" => authority,
                    ":scheme" => Uri.UriSchemeHttps,
                    ":path" => uri.PathAndQuery,
                    _ => string.Empty,
                };
                headers.Add(new KeyValuePair<string, string>(pseudo, value));
            }

            // Use NonValidated so structured headers (User-Agent, Accept-Language, ...) are emitted as the
            // raw single value rather than re-parsed/split into product tokens.
            foreach (var header in request.Headers.NonValidated)
            {
                string name = header.Key.ToLowerInvariant();
                if (name == "host" || IsForbiddenH2Header(name)) continue;
                foreach (var v in header.Value) headers.Add(new KeyValuePair<string, string>(name, v));
            }
            if (request.Content != null)
            {
                foreach (var header in request.Content.Headers.NonValidated)
                {
                    string name = header.Key.ToLowerInvariant();
                    if (IsForbiddenH2Header(name)) continue;
                    foreach (var v in header.Value) headers.Add(new KeyValuePair<string, string>(name, v));
                }
            }

            return HpackEncoder.Encode(headers);
        }

        private static bool IsForbiddenH2Header(string lowerName) => lowerName switch
        {
            "connection" or "keep-alive" or "proxy-connection" or "transfer-encoding" or "upgrade" => true,
            _ => false,
        };

        private async Task<byte[]> ReadResponseBodyAsync(int streamId, CancellationToken ct)
        {
            using var body = new MemoryStream();
            while (true)
            {
                (int length, byte type, byte flags, int sid) = await ReadFrameHeaderAsync(ct).ConfigureAwait(false);
                byte[] payload = length > 0 ? await ReadExactlyAsync(length, ct).ConfigureAwait(false) : Array.Empty<byte>();

                if (Trace != null)
                {
                    string extra = (Http2FrameType)type switch
                    {
                        Http2FrameType.GoAway when payload.Length >= 8 => $" lastStream={(payload[4] << 24) | (payload[5] << 16) | (payload[6] << 8) | payload[7]} err={BeUInt32At(payload, 4)} debug={Encoding.ASCII.GetString(payload, 8, payload.Length - 8)}",
                        Http2FrameType.RstStream when payload.Length >= 4 => $" err={BeUInt32At(payload, 0)}",
                        _ => string.Empty,
                    };
                    Trace($"recv type={(Http2FrameType)type} flags=0x{flags:x2} sid={sid} len={length}{extra}");
                }

                switch ((Http2FrameType)type)
                {
                    case Http2FrameType.Settings:
                        if ((flags & (byte)Http2FrameFlags.Ack) == 0)
                            await WriteRawFrameAsync(Http2FrameType.Settings, (byte)Http2FrameFlags.Ack, 0, Array.Empty<byte>(), ct).ConfigureAwait(false);
                        break;

                    case Http2FrameType.Ping:
                        if ((flags & (byte)Http2FrameFlags.Ack) == 0)
                            await WriteRawFrameAsync(Http2FrameType.Ping, (byte)Http2FrameFlags.Ack, 0, payload, ct).ConfigureAwait(false);
                        break;

                    case Http2FrameType.GoAway:
                        return body.ToArray();

                    case Http2FrameType.RstStream:
                        if (sid == streamId) return body.ToArray();
                        break;

                    case Http2FrameType.Headers:
                        if (sid == streamId && (flags & (byte)Http2FrameFlags.EndStream) != 0) return body.ToArray();
                        break;

                    case Http2FrameType.Data:
                        if (sid == streamId)
                        {
                            WriteData(body, payload, flags);
                            if ((flags & (byte)Http2FrameFlags.EndStream) != 0) return body.ToArray();
                        }
                        break;
                }
            }
        }

        private static void WriteData(MemoryStream body, byte[] payload, byte flags)
        {
            int start = 0;
            int end = payload.Length;
            if ((flags & (byte)Http2FrameFlags.Padded) != 0 && payload.Length > 0)
            {
                int padLength = payload[0];
                start = 1;
                end = payload.Length - padLength;
            }
            if (end > start) body.Write(payload, start, end - start);
        }

        // ---- frame writing (into a buffer) ----

        private void WriteSettingsFrame(Stream s)
        {
            byte[] payload = new byte[_config.Settings.Count * 6];
            int o = 0;
            foreach (var setting in _config.Settings)
            {
                payload[o++] = (byte)(setting.Id >> 8);
                payload[o++] = (byte)setting.Id;
                payload[o++] = (byte)(setting.Value >> 24);
                payload[o++] = (byte)(setting.Value >> 16);
                payload[o++] = (byte)(setting.Value >> 8);
                payload[o++] = (byte)setting.Value;
            }
            WriteFrame(s, Http2FrameType.Settings, 0, 0, payload);
        }

        private void WritePriorityFrame(Stream s, Http2PriorityFrame p)
        {
            byte[] payload = new byte[5];
            uint dep = (uint)p.StreamDependency & 0x7fffffff;
            if (p.Exclusive) dep |= 0x80000000;
            payload[0] = (byte)(dep >> 24);
            payload[1] = (byte)(dep >> 16);
            payload[2] = (byte)(dep >> 8);
            payload[3] = (byte)dep;
            payload[4] = p.Weight;
            WriteFrame(s, Http2FrameType.Priority, 0, p.StreamId, payload);
        }

        private void WriteDataFrames(Stream s, int streamId, byte[] body)
        {
            int offset = 0;
            while (offset < body.Length)
            {
                int chunk = Math.Min(DefaultMaxFrameSize, body.Length - offset);
                bool last = offset + chunk >= body.Length;
                WriteFrame(s, Http2FrameType.Data, (byte)(last ? Http2FrameFlags.EndStream : Http2FrameFlags.None),
                    streamId, body, offset, chunk);
                offset += chunk;
            }
        }

        private static void WriteFrame(Stream s, Http2FrameType type, byte flags, int streamId, byte[] payload)
            => WriteFrame(s, type, flags, streamId, payload, 0, payload.Length);

        private static void WriteFrame(Stream s, Http2FrameType type, byte flags, int streamId, byte[] payload, int offset, int length)
        {
            s.WriteByte((byte)(length >> 16));
            s.WriteByte((byte)(length >> 8));
            s.WriteByte((byte)length);
            s.WriteByte((byte)type);
            s.WriteByte(flags);
            s.WriteByte((byte)((streamId >> 24) & 0x7f));
            s.WriteByte((byte)(streamId >> 16));
            s.WriteByte((byte)(streamId >> 8));
            s.WriteByte((byte)streamId);
            if (length > 0) s.Write(payload, offset, length);
        }

        private async Task WriteRawFrameAsync(Http2FrameType type, byte flags, int streamId, byte[] payload, CancellationToken ct)
        {
            byte[] frame = new byte[9 + payload.Length];
            int len = payload.Length;
            frame[0] = (byte)(len >> 16);
            frame[1] = (byte)(len >> 8);
            frame[2] = (byte)len;
            frame[3] = (byte)type;
            frame[4] = flags;
            frame[5] = (byte)((streamId >> 24) & 0x7f);
            frame[6] = (byte)(streamId >> 16);
            frame[7] = (byte)(streamId >> 8);
            frame[8] = (byte)streamId;
            if (len > 0) Buffer.BlockCopy(payload, 0, frame, 9, len);
            await _stream.WriteAsync(frame, 0, frame.Length, ct).ConfigureAwait(false);
            await _stream.FlushAsync(ct).ConfigureAwait(false);
        }

        // ---- frame reading ----

        private async Task<(int length, byte type, byte flags, int streamId)> ReadFrameHeaderAsync(CancellationToken ct)
        {
            await ReadExactIntoAsync(_frameHeader, 9, ct).ConfigureAwait(false);
            int length = (_frameHeader[0] << 16) | (_frameHeader[1] << 8) | _frameHeader[2];
            byte type = _frameHeader[3];
            byte flags = _frameHeader[4];
            int streamId = ((_frameHeader[5] & 0x7f) << 24) | (_frameHeader[6] << 16) | (_frameHeader[7] << 8) | _frameHeader[8];
            return (length, type, flags, streamId);
        }

        private async Task<byte[]> ReadExactlyAsync(int count, CancellationToken ct)
        {
            byte[] buffer = new byte[count];
            await ReadExactIntoAsync(buffer, count, ct).ConfigureAwait(false);
            return buffer;
        }

        private async Task ReadExactIntoAsync(byte[] buffer, int count, CancellationToken ct)
        {
            int read = 0;
            while (read < count)
            {
                int n = await _stream.ReadAsync(buffer.AsMemory(read, count - read), ct).ConfigureAwait(false);
                if (n == 0) throw new IOException("Unexpected end of HTTP/2 stream.");
                read += n;
            }
        }

        private static byte[] BeUInt32(uint value) => new[]
        {
            (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value,
        };

        private static uint BeUInt32At(byte[] b, int o)
            => ((uint)b[o] << 24) | ((uint)b[o + 1] << 16) | ((uint)b[o + 2] << 8) | b[o + 3];
    }
}
