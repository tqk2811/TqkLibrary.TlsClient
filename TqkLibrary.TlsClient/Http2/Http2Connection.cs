using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.TlsClient.Http2.Enums;
using TqkLibrary.TlsClient.Http2.Hpack;
using TqkLibrary.TlsClient.Http2.Models;

namespace TqkLibrary.TlsClient.Http2
{
    /// <summary>
    /// A multiplexed HTTP/2 client over a plaintext stream (e.g. an authenticated ImpersonatedTlsStream). It
    /// emits the connection preface, SETTINGS, connection WINDOW_UPDATE and PRIORITY frames exactly as an
    /// <see cref="Http2FingerprintConfig"/> describes (so the Akamai h2 fingerprint matches the configured
    /// browser), honors flow control both ways, and streams response bodies.
    ///
    /// A single background reader loop demultiplexes incoming frames to per-stream queues, so MANY requests
    /// can be in flight concurrently on one connection (like a real browser, which multiplexes instead of
    /// opening N parallel connections). All writes are serialized; HPACK decoding happens only on the reader
    /// thread, keeping the dynamic table in sync.
    /// </summary>
    public sealed class Http2Connection : IDisposable
    {
        private static readonly byte[] Preface = Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

        private readonly Stream _stream;
        private readonly Http2FingerprintConfig _config;
        private readonly HpackDecoder _hpack;

        private readonly SemaphoreSlim _writeLock = new(1, 1);
        private readonly object _stateLock = new();
        private readonly object _windowLock = new();
        private readonly ConcurrentDictionary<int, StreamState> _streams = new();
        private readonly CancellationTokenSource _lifetime = new();
        private readonly AsyncWaiter _windowWaiter = new();

        // reader loop's private frame-header buffer (only the reader reads from _stream)
        private readonly byte[] _readHeader = new byte[9];
        private readonly MemoryStream _hdrBuf = new();
        private int _hdrStreamId;
        private bool _hdrEndStream;
        private bool _expectContinuation;

        private Task? _readerTask;
        private bool _started;          // preface/SETTINGS written (guarded by _writeLock)
        private int _nextStreamId = 1;  // allocated under _writeLock so HEADERS go out in increasing id order

        private bool _faulted;          // guarded by _stateLock
        private bool _goAway;           // guarded by _stateLock
        private bool _disposed;         // guarded by _stateLock
        private Exception? _faultError;
        private int _activeStreams;     // guarded by _stateLock
        private int _maxConcurrentStreams = 100; // guarded by _stateLock; updated from server SETTINGS

        // send-side flow control (guarded by _windowLock)
        private long _connSendWindow = 65535;
        private int _serverInitialWindow = 65535;
        private int _serverMaxFrameSize = 16384;

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

        /// <summary>True while the connection can still carry new streams (not faulted/closed/GOAWAY'd).</summary>
        internal bool IsUsable
        {
            get { lock (_stateLock) return !_faulted && !_goAway && !_disposed; }
        }

        /// <summary>
        /// Atomically reserves a concurrent-stream slot. Returns false when the connection is unusable or at
        /// the server's MAX_CONCURRENT_STREAMS limit (the caller should open a new connection instead).
        /// </summary>
        internal bool TryBeginStream()
        {
            lock (_stateLock)
            {
                if (_faulted || _goAway || _disposed) return false;
                if (_activeStreams >= _maxConcurrentStreams) return false;
                _activeStreams++;
                return true;
            }
        }

        /// <summary>Sends a request, reserving a stream slot first (throws if the connection is unusable).</summary>
        public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (!TryBeginStream())
                throw new IOException("HTTP/2 connection is not usable.", _faultError);
            return SendReservedAsync(request, cancellationToken);
        }

        /// <summary>Sends a request on a slot already reserved via <see cref="TryBeginStream"/>.</summary>
        internal async Task<HttpResponseMessage> SendReservedAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            StreamState? st = null;
            bool handed = false;
            try
            {
                byte[]? body = request.Content != null
                    ? await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false)
                    : null;
                bool hasBody = body is { Length: > 0 };

                await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
                bool sentPreface;
                try
                {
                    EnsureReaderStarted();
                    st = new StreamState();
                    lock (_windowLock) st.SendWindow = _serverInitialWindow;
                    st.Id = _nextStreamId;
                    _nextStreamId += 2;
                    _streams[st.Id] = st;

                    sentPreface = !_started;
                    using var outBuf = new MemoryStream();
                    if (!_started)
                    {
                        outBuf.Write(Preface, 0, Preface.Length);
                        WriteSettingsFrame(outBuf);
                        if (_config.ConnectionWindowUpdateIncrement > 0)
                            WriteFrame(outBuf, Http2FrameType.WindowUpdate, 0, 0, BeUInt32(_config.ConnectionWindowUpdateIncrement));
                        foreach (var p in _config.Priorities)
                            WritePriorityFrame(outBuf, p);
                        _started = true;
                    }

                    byte[] headerBlock = BuildHeaderBlock(request);
                    WriteFrame(outBuf, Http2FrameType.Headers,
                        (byte)(Http2FrameFlags.EndHeaders | (hasBody ? 0 : Http2FrameFlags.EndStream)),
                        st.Id, headerBlock);

                    byte[] toSend = outBuf.ToArray();
                    Trace?.Invoke($"send {toSend.Length}B preface={sentPreface} stream={st.Id}");
                    await _stream.WriteAsync(toSend, 0, toSend.Length, cancellationToken).ConfigureAwait(false);
                    await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    _writeLock.Release();
                }

                if (hasBody)
                    await SendBodyAsync(st, body!, cancellationToken).ConfigureAwait(false);

                List<KeyValuePair<string, string>> responseHeaders;
                try
                {
                    responseHeaders = await st.Headers.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    await TryResetAsync(st.Id, Http2ErrorCode.Cancel).ConfigureAwait(false);
                    throw;
                }

                var bodyStream = new Http2ResponseStream(this, st);
                HttpResponseMessage response = BuildResponse(responseHeaders, bodyStream, request);
                handed = true;
                return response;
            }
            finally
            {
                if (!handed) ReleaseReservation(st);
            }
        }

        private void EnsureReaderStarted()
        {
            // Called under _writeLock, so the loop starts exactly once and after the preface is queued.
            _readerTask ??= Task.Run(ReaderLoopAsync);
        }

        // ---- sending the request body (send-side flow control) ----

        private async Task SendBodyAsync(StreamState st, byte[] body, CancellationToken ct)
        {
            int offset = 0;
            while (offset < body.Length)
            {
                if (!IsUsable) throw new IOException("HTTP/2 connection closed while sending the request body.", _faultError);

                Task wait = _windowWaiter.WaitAsync();
                int chunk = 0;
                lock (_windowLock)
                {
                    long avail = Math.Min(_connSendWindow, st.SendWindow);
                    if (avail > 0)
                    {
                        int max = Math.Min(_serverMaxFrameSize, body.Length - offset);
                        chunk = (int)Math.Min(avail, max);
                        _connSendWindow -= chunk;
                        st.SendWindow -= chunk;
                    }
                }

                if (chunk == 0)
                {
                    await wait.WaitAsync(ct).ConfigureAwait(false); // woken by a WINDOW_UPDATE or a fault
                    continue;
                }

                bool last = offset + chunk >= body.Length;
                await WriteFrameLockedAsync(Http2FrameType.Data,
                    (byte)(last ? Http2FrameFlags.EndStream : Http2FrameFlags.None), st.Id, body, offset, chunk, ct).ConfigureAwait(false);
                offset += chunk;
            }
        }

        // ---- background reader loop ----

        private async Task ReaderLoopAsync()
        {
            try
            {
                while (true)
                {
                    Frame f = await ReadFrameAsync(_lifetime.Token).ConfigureAwait(false);
                    if (Trace != null) Trace($"recv type={(Http2FrameType)f.Type} flags=0x{f.Flags:x2} sid={f.StreamId} len={f.Length}");

                    switch ((Http2FrameType)f.Type)
                    {
                        case Http2FrameType.Settings:
                            if ((f.Flags & (byte)Http2FrameFlags.Ack) == 0)
                            {
                                ApplyServerSettings(f.Payload);
                                await WriteFrameLockedAsync(Http2FrameType.Settings, (byte)Http2FrameFlags.Ack, 0, Array.Empty<byte>(), _lifetime.Token).ConfigureAwait(false);
                            }
                            break;

                        case Http2FrameType.Ping:
                            if ((f.Flags & (byte)Http2FrameFlags.Ack) == 0)
                                await WriteFrameLockedAsync(Http2FrameType.Ping, (byte)Http2FrameFlags.Ack, 0, f.Payload, _lifetime.Token).ConfigureAwait(false);
                            break;

                        case Http2FrameType.WindowUpdate:
                            HandleWindowUpdate(f);
                            break;

                        case Http2FrameType.Headers:
                            HandleHeaders(f);
                            break;

                        case Http2FrameType.Continuation:
                            HandleContinuation(f);
                            break;

                        case Http2FrameType.Data:
                            await HandleDataAsync(f).ConfigureAwait(false);
                            break;

                        case Http2FrameType.RstStream:
                            HandleRst(f);
                            break;

                        case Http2FrameType.GoAway:
                            HandleGoAway(f);
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                Fault(ex);
            }
        }

        private void ApplyServerSettings(byte[] payload)
        {
            for (int i = 0; i + 6 <= payload.Length; i += 6)
            {
                ushort id = (ushort)((payload[i] << 8) | payload[i + 1]);
                uint value = BeUInt32At(payload, i + 2);
                switch ((Http2SettingId)id)
                {
                    case Http2SettingId.InitialWindowSize:
                        lock (_windowLock)
                        {
                            long delta = (long)value - _serverInitialWindow;
                            _serverInitialWindow = (int)value;
                            foreach (var st in _streams.Values) st.SendWindow += delta;
                        }
                        break;
                    case Http2SettingId.MaxConcurrentStreams:
                        lock (_stateLock) _maxConcurrentStreams = value > int.MaxValue ? int.MaxValue : (int)value;
                        break;
                    case Http2SettingId.MaxFrameSize:
                        lock (_windowLock) _serverMaxFrameSize = (int)value;
                        break;
                }
            }
            _windowWaiter.Set();
        }

        private void HandleWindowUpdate(Frame f)
        {
            if (f.Payload.Length < 4) return;
            long inc = BeUInt32At(f.Payload, 0) & 0x7fffffff;
            if (inc == 0) return;
            if (f.StreamId == 0)
                lock (_windowLock) _connSendWindow += inc;
            else if (_streams.TryGetValue(f.StreamId, out var st))
                lock (_windowLock) st.SendWindow += inc;
            _windowWaiter.Set();
        }

        private void HandleHeaders(Frame f)
        {
            if (_expectContinuation) throw new IOException("Expected CONTINUATION frame, got HEADERS.");
            _hdrBuf.SetLength(0);
            _hdrStreamId = f.StreamId;
            _hdrEndStream = (f.Flags & (byte)Http2FrameFlags.EndStream) != 0;
            byte[] fragment = ExtractHeaderBlockFragment(f.Payload, f.Flags);
            _hdrBuf.Write(fragment, 0, fragment.Length);
            if ((f.Flags & (byte)Http2FrameFlags.EndHeaders) != 0) FinishHeaderBlock();
            else _expectContinuation = true;
        }

        private void HandleContinuation(Frame f)
        {
            if (!_expectContinuation || f.StreamId != _hdrStreamId) throw new IOException("Unexpected CONTINUATION frame.");
            _hdrBuf.Write(f.Payload, 0, f.Payload.Length);
            if ((f.Flags & (byte)Http2FrameFlags.EndHeaders) != 0)
            {
                _expectContinuation = false;
                FinishHeaderBlock();
            }
        }

        private void FinishHeaderBlock()
        {
            // Always decode (even for unknown/pushed streams) to keep the HPACK dynamic table in sync.
            List<KeyValuePair<string, string>> headers = _hpack.Decode(_hdrBuf.ToArray());
            if (_streams.TryGetValue(_hdrStreamId, out var st))
            {
                st.Headers.TrySetResult(headers);
                if (_hdrEndStream) st.Data.Writer.TryComplete();
            }
        }

        private async Task HandleDataAsync(Frame f)
        {
            int wire = f.Length;
            // Connection-level flow control: replenish immediately so a slow consumer can't stall the whole
            // connection (stream-level flow control is replenished by the consumer for backpressure).
            if (wire > 0) await ReplenishAsync(0, wire).ConfigureAwait(false);

            if (_streams.TryGetValue(f.StreamId, out var st))
            {
                bool end = (f.Flags & (byte)Http2FrameFlags.EndStream) != 0;
                byte[] data = ExtractData(f.Payload, f.Flags);
                st.Data.Writer.TryWrite(new DataChunk(data, wire, end));
                if (end) st.Data.Writer.TryComplete();
            }
        }

        private void HandleRst(Frame f)
        {
            if (_streams.TryGetValue(f.StreamId, out var st))
            {
                var ex = new IOException($"Server reset HTTP/2 stream {f.StreamId}.");
                st.Headers.TrySetException(ex);
                st.Data.Writer.TryComplete(ex);
            }
        }

        private void HandleGoAway(Frame f)
        {
            lock (_stateLock) _goAway = true;
            int lastId = f.Payload.Length >= 4 ? (int)(BeUInt32At(f.Payload, 0) & 0x7fffffff) : int.MaxValue;
            foreach (var kv in _streams)
            {
                if (kv.Key > lastId)
                {
                    var ex = new IOException("HTTP/2 stream refused by GOAWAY.");
                    kv.Value.Headers.TrySetException(ex);
                    kv.Value.Data.Writer.TryComplete(ex);
                }
            }
        }

        private void Fault(Exception ex)
        {
            lock (_stateLock)
            {
                if (_faulted) return;
                _faulted = true;
                _faultError = ex;
            }
            _windowWaiter.Set();
            foreach (var st in _streams.Values)
            {
                st.Headers.TrySetException(ex);
                st.Data.Writer.TryComplete(ex);
            }
            try { _stream.Dispose(); } catch { /* best effort */ }
        }

        // ---- per-stream lifetime accounting ----

        private void ReleaseReservation(StreamState? st)
        {
            if (st != null)
            {
                _streams.TryRemove(st.Id, out _);
                st.Data.Writer.TryComplete();
            }
            lock (_stateLock)
            {
                if (st != null)
                {
                    if (st.Ended) return;
                    st.Ended = true;
                }
                _activeStreams--;
            }
        }

        private void OnStreamConsumerDisposed(StreamState st, bool drained)
        {
            _streams.TryRemove(st.Id, out _);
            st.Data.Writer.TryComplete();
            if (!drained && IsUsable)
                _ = TryResetAsync(st.Id, Http2ErrorCode.Cancel); // tell the server to stop sending
            lock (_stateLock)
            {
                if (st.Ended) return;
                st.Ended = true;
                _activeStreams--;
            }
        }

        private async Task TryResetAsync(int streamId, Http2ErrorCode code)
        {
            try
            {
                if (IsUsable)
                    await WriteFrameLockedAsync(Http2FrameType.RstStream, 0, streamId, BeUInt32((uint)code), _lifetime.Token).ConfigureAwait(false);
            }
            catch { /* best effort */ }
        }

        private Task ReplenishAsync(int streamId, int length)
            => WriteFrameLockedAsync(Http2FrameType.WindowUpdate, 0, streamId, BeUInt32((uint)length), _lifetime.Token);

        // ---- header block / response construction ----

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

        private static HttpResponseMessage BuildResponse(List<KeyValuePair<string, string>> headers, Stream bodyStream, HttpRequestMessage request)
        {
            var response = new HttpResponseMessage { Version = HttpVersion.Version20, RequestMessage = request };
            foreach (var h in headers)
                if (h.Key == ":status" && int.TryParse(h.Value, out int code))
                    response.StatusCode = (HttpStatusCode)code;

            var content = new StreamContent(bodyStream);
            response.Content = content;
            foreach (var h in headers)
            {
                if (h.Key.Length > 0 && h.Key[0] == ':') continue;
                if (!response.Headers.TryAddWithoutValidation(h.Key, h.Value))
                    content.Headers.TryAddWithoutValidation(h.Key, h.Value);
            }
            return response;
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

        private Task WriteFrameLockedAsync(Http2FrameType type, byte flags, int streamId, byte[] payload, CancellationToken ct)
            => WriteFrameLockedAsync(type, flags, streamId, payload, 0, payload.Length, ct);

        private async Task WriteFrameLockedAsync(Http2FrameType type, byte flags, int streamId, byte[] payload, int offset, int length, CancellationToken ct)
        {
            await _writeLock.WaitAsync(ct).ConfigureAwait(false);
            try
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
            finally
            {
                _writeLock.Release();
            }
        }

        // ---- frame reading (reader loop only) ----

        private async Task<Frame> ReadFrameAsync(CancellationToken ct)
        {
            await ReadExactIntoAsync(_readHeader, 9, ct).ConfigureAwait(false);
            int length = (_readHeader[0] << 16) | (_readHeader[1] << 8) | _readHeader[2];
            byte type = _readHeader[3];
            byte flags = _readHeader[4];
            int streamId = ((_readHeader[5] & 0x7f) << 24) | (_readHeader[6] << 16) | (_readHeader[7] << 8) | _readHeader[8];
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

        private static byte[] ExtractData(byte[] payload, byte flags)
        {
            int start = 0;
            int end = payload.Length;
            if ((flags & (byte)Http2FrameFlags.Padded) != 0 && payload.Length > 0)
            {
                int padLength = payload[0];
                start = 1;
                end = payload.Length - padLength;
            }
            if (end <= start) return Array.Empty<byte>();
            return payload[start..end];
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
                start += 5;
            if (end < start) end = start;
            return payload[start..end];
        }

        private static byte[] BeUInt32(uint value) => new[]
        {
            (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value,
        };

        private static uint BeUInt32At(byte[] b, int o)
            => ((uint)b[o] << 24) | ((uint)b[o + 1] << 16) | ((uint)b[o + 2] << 8) | b[o + 3];

        public void Dispose()
        {
            lock (_stateLock)
            {
                if (_disposed) return;
                _disposed = true;
            }
            _lifetime.Cancel();
            try { _stream.Dispose(); } catch { /* best effort */ }
            _windowWaiter.Set();
            foreach (var st in _streams.Values)
            {
                st.Headers.TrySetException(new ObjectDisposedException(nameof(Http2Connection)));
                st.Data.Writer.TryComplete();
            }
        }

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

        private readonly struct DataChunk
        {
            public DataChunk(byte[] data, int wireLength, bool endStream)
            {
                Data = data; WireLength = wireLength; EndStream = endStream;
            }
            public byte[] Data { get; }
            public int WireLength { get; }
            public bool EndStream { get; }
        }

        /// <summary>Per-stream demultiplexing state: response headers, an incoming-DATA queue, and the send window.</summary>
        private sealed class StreamState
        {
            public int Id;
            public long SendWindow;
            public bool Ended; // accounting done (guarded by the connection's _stateLock)

            public readonly TaskCompletionSource<List<KeyValuePair<string, string>>> Headers
                = new(TaskCreationOptions.RunContinuationsAsynchronously);

            public readonly Channel<DataChunk> Data = Channel.CreateUnbounded<DataChunk>(
                new UnboundedChannelOptions { SingleReader = true, SingleWriter = true });
        }

        /// <summary>A TaskCompletionSource-backed signal that wakes body senders when a WINDOW_UPDATE arrives.</summary>
        private sealed class AsyncWaiter
        {
            private volatile TaskCompletionSource<bool> _tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
            public Task WaitAsync() => _tcs.Task;
            public void Set()
            {
                TaskCompletionSource<bool> prev = Interlocked.Exchange(
                    ref _tcs, new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously));
                prev.TrySetResult(true);
            }
        }

        /// <summary>Streams one stream's response DATA frames; replenishes the stream window as data is consumed.</summary>
        private sealed class Http2ResponseStream : Stream
        {
            private readonly Http2Connection _conn;
            private readonly StreamState _st;
            private byte[] _leftover = Array.Empty<byte>();
            private int _leftoverPos;
            private bool _ended;
            private bool _disposed;

            public Http2ResponseStream(Http2Connection conn, StreamState st)
            {
                _conn = conn;
                _st = st;
            }

            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
            {
                if (_leftoverPos < _leftover.Length) return CopyLeftover(buffer.Span);
                if (_ended) return 0;

                while (true)
                {
                    if (!_st.Data.Reader.TryRead(out DataChunk chunk))
                    {
                        bool more;
                        try { more = await _st.Data.Reader.WaitToReadAsync(ct).ConfigureAwait(false); }
                        catch (ChannelClosedException) { _ended = true; return 0; }
                        if (!more) { _ended = true; return 0; }
                        continue;
                    }

                    // Stream-level flow control (connection-level was already replenished by the reader loop).
                    if (chunk.WireLength > 0 && !chunk.EndStream)
                        await _conn.ReplenishAsync(_st.Id, chunk.WireLength).ConfigureAwait(false);

                    if (chunk.Data.Length == 0)
                    {
                        if (chunk.EndStream) { _ended = true; return 0; }
                        continue;
                    }

                    _leftover = chunk.Data;
                    _leftoverPos = 0;
                    return CopyLeftover(buffer.Span);
                }
            }

            private int CopyLeftover(Span<byte> buffer)
            {
                int n = Math.Min(buffer.Length, _leftover.Length - _leftoverPos);
                _leftover.AsSpan(_leftoverPos, n).CopyTo(buffer);
                _leftoverPos += n;
                return n;
            }

            public override int Read(byte[] buffer, int offset, int count)
                => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
                => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

            protected override void Dispose(bool disposing)
            {
                if (disposing && !_disposed)
                {
                    _disposed = true;
                    bool drained = _ended && _leftoverPos >= _leftover.Length;
                    _conn.OnStreamConsumerDisposed(_st, drained);
                }
                base.Dispose(disposing);
            }

            public override bool CanRead => true;
            public override bool CanWrite => false;
            public override bool CanSeek => false;
            public override void Flush() { }
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }
    }
}
