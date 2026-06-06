using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
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
    /// matches the configured browser), honors flow control in both directions, then decodes the response.
    ///
    /// One request per connection (no multiplexing/pooling yet); the response body is buffered.
    /// </summary>
    public sealed class Http2Connection
    {
        private static readonly byte[] Preface = Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        private const int DefaultMaxFrameSize = 16384;
        private const int StreamId = 1;

        private readonly Stream _stream;
        private readonly Http2FingerprintConfig _config;
        private readonly HpackDecoder _hpack;
        private readonly byte[] _frameHeader = new byte[9];

        // Send-side flow control (how much the server lets us send).
        private long _connSendWindow = 65535;
        private long _streamSendWindow = 65535;
        private int _serverInitialWindow = 65535;

        // Frames read while sending the request body (full-duplex) are stashed for the response reader.
        private readonly Queue<Frame> _stash = new();

        public Http2Connection(Stream stream, Http2FingerprintConfig config)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
            _config = config ?? throw new ArgumentNullException(nameof(config));

            int headerTableSize = 65536;
            foreach (var s in config.Settings)
                if (s.Id == (ushort)Http2SettingId.HeaderTableSize)
                    headerTableSize = (int)s.Value;
            _hpack = new HpackDecoder(headerTableSize);
        }

        /// <summary>Optional diagnostic sink for sent/received frames (debugging).</summary>
        public Action<string>? Trace { get; set; }

        private readonly struct Frame
        {
            public Frame(int length, byte type, byte flags, int streamId, byte[] payload)
            {
                Length = length; Type = type; Flags = flags; StreamId = streamId; Payload = payload;
            }
            public int Length { get; }
            public byte Type { get; }
            public byte Flags { get; }
            public int StreamId { get; }
            public byte[] Payload { get; }
        }

        public async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            byte[]? body = request.Content != null
                ? await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false)
                : null;
            bool hasBody = body is { Length: > 0 };

            using (var outBuf = new MemoryStream())
            {
                outBuf.Write(Preface, 0, Preface.Length);
                WriteSettingsFrame(outBuf);
                if (_config.ConnectionWindowUpdateIncrement > 0)
                    WriteFrame(outBuf, Http2FrameType.WindowUpdate, 0, 0, BeUInt32(_config.ConnectionWindowUpdateIncrement));
                foreach (var p in _config.Priorities)
                    WritePriorityFrame(outBuf, p);

                byte[] headerBlock = BuildHeaderBlock(request);
                WriteFrame(outBuf, Http2FrameType.Headers,
                    (byte)(Http2FrameFlags.EndHeaders | (hasBody ? 0 : Http2FrameFlags.EndStream)),
                    StreamId, headerBlock);

                byte[] toSend = outBuf.ToArray();
                Trace?.Invoke("send " + Convert.ToHexString(toSend));
                await _stream.WriteAsync(toSend, 0, toSend.Length, cancellationToken).ConfigureAwait(false);
                await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            if (hasBody)
                await SendBodyAsync(body!, cancellationToken).ConfigureAwait(false);

            return await ReadResponseAsync(request, cancellationToken).ConfigureAwait(false);
        }

        private async Task SendBodyAsync(byte[] body, CancellationToken ct)
        {
            int offset = 0;
            while (offset < body.Length)
            {
                // Wait until both the stream and connection send windows have room.
                while (_streamSendWindow <= 0 || _connSendWindow <= 0)
                {
                    Frame f = await NextFrameAsync(ct).ConfigureAwait(false);
                    if (!await TryHandleControlFrameAsync(f, ct).ConfigureAwait(false))
                        _stash.Enqueue(f); // response frame arrived early (full-duplex) — replay it later
                }

                int allowed = (int)Math.Min(Math.Min(_streamSendWindow, _connSendWindow), DefaultMaxFrameSize);
                int chunk = Math.Min(allowed, body.Length - offset);
                bool last = offset + chunk >= body.Length;
                await WriteRawFrameAsync(Http2FrameType.Data,
                    (byte)(last ? Http2FrameFlags.EndStream : Http2FrameFlags.None), StreamId, body, offset, chunk, ct).ConfigureAwait(false);
                offset += chunk;
                _streamSendWindow -= chunk;
                _connSendWindow -= chunk;
            }
        }

        private async Task<HttpResponseMessage> ReadResponseAsync(HttpRequestMessage request, CancellationToken ct)
        {
            using var body = new MemoryStream();
            using var headerBlock = new MemoryStream();
            List<KeyValuePair<string, string>>? responseHeaders = null;
            bool endStream = false;
            bool expectingContinuation = false;

            while (!endStream)
            {
                Frame f = await NextFrameAsync(ct).ConfigureAwait(false);
                var frameType = (Http2FrameType)f.Type;

                if (Trace != null) Trace($"recv type={frameType} flags=0x{f.Flags:x2} sid={f.StreamId} len={f.Length}");

                if (expectingContinuation && !(frameType == Http2FrameType.Continuation && f.StreamId == StreamId))
                    throw new IOException("Expected CONTINUATION frame.");

                if (await TryHandleControlFrameAsync(f, ct).ConfigureAwait(false))
                    continue;

                switch (frameType)
                {
                    case Http2FrameType.GoAway:
                        if (responseHeaders is null) throw new IOException("Server sent GOAWAY before responding.");
                        endStream = true;
                        break;

                    case Http2FrameType.RstStream:
                        if (f.StreamId == StreamId)
                        {
                            if (responseHeaders is null) throw new IOException("Server reset the stream before responding.");
                            endStream = true;
                        }
                        break;

                    case Http2FrameType.Headers:
                        if (f.StreamId == StreamId)
                        {
                            if (responseHeaders is null)
                            {
                                byte[] fragment = ExtractHeaderBlockFragment(f.Payload, f.Flags);
                                headerBlock.Write(fragment, 0, fragment.Length);
                            }
                            bool endHeaders = (f.Flags & (byte)Http2FrameFlags.EndHeaders) != 0;
                            expectingContinuation = !endHeaders;
                            if (responseHeaders is null && endHeaders)
                            {
                                responseHeaders = _hpack.Decode(headerBlock.ToArray());
                                headerBlock.SetLength(0);
                            }
                            if ((f.Flags & (byte)Http2FrameFlags.EndStream) != 0) endStream = true;
                        }
                        break;

                    case Http2FrameType.Continuation:
                        if (f.StreamId == StreamId)
                        {
                            if (responseHeaders is null) headerBlock.Write(f.Payload, 0, f.Payload.Length);
                            bool endHeaders = (f.Flags & (byte)Http2FrameFlags.EndHeaders) != 0;
                            expectingContinuation = !endHeaders;
                            if (responseHeaders is null && endHeaders)
                            {
                                responseHeaders = _hpack.Decode(headerBlock.ToArray());
                                headerBlock.SetLength(0);
                            }
                        }
                        break;

                    case Http2FrameType.Data:
                        if (f.StreamId == StreamId)
                        {
                            WriteData(body, f.Payload, f.Flags);
                            bool dataEnd = (f.Flags & (byte)Http2FrameFlags.EndStream) != 0;
                            // Replenish the flow-control windows this DATA frame consumed (full payload length).
                            if (f.Length > 0)
                            {
                                await WriteRawFrameAsync(Http2FrameType.WindowUpdate, 0, 0, BeUInt32((uint)f.Length), ct).ConfigureAwait(false);
                                if (!dataEnd)
                                    await WriteRawFrameAsync(Http2FrameType.WindowUpdate, 0, StreamId, BeUInt32((uint)f.Length), ct).ConfigureAwait(false);
                            }
                            if (dataEnd) endStream = true;
                        }
                        break;
                }
            }

            return BuildResponse(responseHeaders!, body.ToArray(), request);
        }

        // Handles SETTINGS / PING / WINDOW_UPDATE (which both the send and receive paths must process).
        // Returns true if the frame was a control frame and has been handled.
        private async Task<bool> TryHandleControlFrameAsync(Frame f, CancellationToken ct)
        {
            switch ((Http2FrameType)f.Type)
            {
                case Http2FrameType.Settings:
                    if ((f.Flags & (byte)Http2FrameFlags.Ack) == 0)
                    {
                        ApplyServerSettings(f.Payload);
                        await WriteRawFrameAsync(Http2FrameType.Settings, (byte)Http2FrameFlags.Ack, 0, Array.Empty<byte>(), 0, 0, ct).ConfigureAwait(false);
                    }
                    return true;

                case Http2FrameType.Ping:
                    if ((f.Flags & (byte)Http2FrameFlags.Ack) == 0)
                        await WriteRawFrameAsync(Http2FrameType.Ping, (byte)Http2FrameFlags.Ack, 0, f.Payload, 0, f.Payload.Length, ct).ConfigureAwait(false);
                    return true;

                case Http2FrameType.WindowUpdate:
                    if (f.Payload.Length >= 4)
                    {
                        long inc = BeUInt32At(f.Payload, 0) & 0x7fffffff;
                        if (f.StreamId == 0) _connSendWindow += inc;
                        else if (f.StreamId == StreamId) _streamSendWindow += inc;
                    }
                    return true;
            }
            return false;
        }

        private void ApplyServerSettings(byte[] payload)
        {
            for (int i = 0; i + 6 <= payload.Length; i += 6)
            {
                ushort id = (ushort)((payload[i] << 8) | payload[i + 1]);
                uint value = BeUInt32At(payload, i + 2);
                if (id == (ushort)Http2SettingId.InitialWindowSize)
                {
                    // Adjusting SETTINGS_INITIAL_WINDOW_SIZE retroactively shifts open streams' send windows.
                    _streamSendWindow += (long)value - _serverInitialWindow;
                    _serverInitialWindow = (int)value;
                }
            }
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

        private static HttpResponseMessage BuildResponse(List<KeyValuePair<string, string>> headers, byte[] body, HttpRequestMessage request)
        {
            var response = new HttpResponseMessage { Version = HttpVersion.Version20, RequestMessage = request };
            foreach (var h in headers)
                if (h.Key == ":status" && int.TryParse(h.Value, out int code))
                    response.StatusCode = (HttpStatusCode)code;

            response.Content = new ByteArrayContent(body);
            foreach (var h in headers)
            {
                if (h.Key.Length > 0 && h.Key[0] == ':') continue;          // pseudo-headers
                if (string.Equals(h.Key, "content-length", StringComparison.OrdinalIgnoreCase)) continue; // set by ByteArrayContent
                if (!response.Headers.TryAddWithoutValidation(h.Key, h.Value))
                    response.Content.Headers.TryAddWithoutValidation(h.Key, h.Value);
            }
            return response;
        }

        private static byte[] ExtractHeaderBlockFragment(byte[] payload, byte flags)
        {
            int start = 0;
            int end = payload.Length;
            if ((flags & (byte)Http2FrameFlags.Padded) != 0 && payload.Length > 0)
            {
                int padLength = payload[0];
                start = 1;
                end = payload.Length - padLength;
            }
            if ((flags & (byte)Http2FrameFlags.Priority) != 0)
                start += 5; // exclusive(1) + stream dependency(31) + weight(8)

            if (end < start) end = start;
            return payload[start..end];
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

        // ---- frame writing ----

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

        private async Task WriteRawFrameAsync(Http2FrameType type, byte flags, int streamId, byte[] payload, int offset, int length, CancellationToken ct)
        {
            byte[] frame = new byte[9 + length];
            frame[0] = (byte)(length >> 16);
            frame[1] = (byte)(length >> 8);
            frame[2] = (byte)length;
            frame[3] = (byte)type;
            frame[4] = flags;
            frame[5] = (byte)((streamId >> 24) & 0x7f);
            frame[6] = (byte)(streamId >> 16);
            frame[7] = (byte)(streamId >> 8);
            frame[8] = (byte)streamId;
            if (length > 0) Buffer.BlockCopy(payload, offset, frame, 9, length);
            await _stream.WriteAsync(frame, 0, frame.Length, ct).ConfigureAwait(false);
            await _stream.FlushAsync(ct).ConfigureAwait(false);
        }

        private Task WriteRawFrameAsync(Http2FrameType type, byte flags, int streamId, byte[] payload, CancellationToken ct)
            => WriteRawFrameAsync(type, flags, streamId, payload, 0, payload.Length, ct);

        // ---- frame reading ----

        private async Task<Frame> NextFrameAsync(CancellationToken ct)
        {
            if (_stash.Count > 0) return _stash.Dequeue();
            await ReadExactIntoAsync(_frameHeader, 9, ct).ConfigureAwait(false);
            int length = (_frameHeader[0] << 16) | (_frameHeader[1] << 8) | _frameHeader[2];
            byte type = _frameHeader[3];
            byte flags = _frameHeader[4];
            int streamId = ((_frameHeader[5] & 0x7f) << 24) | (_frameHeader[6] << 16) | (_frameHeader[7] << 8) | _frameHeader[8];
            byte[] payload = length > 0 ? await ReadExactlyAsync(length, ct).ConfigureAwait(false) : Array.Empty<byte>();
            return new Frame(length, type, flags, streamId, payload);
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
