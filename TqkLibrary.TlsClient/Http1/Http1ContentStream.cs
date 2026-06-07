using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.TlsClient.Http1
{
    /// <summary>
    /// Read-only response body stream that applies HTTP/1.1 framing on top of a raw stream:
    /// Content-Length, Transfer-Encoding: chunked, or read-until-close. It first drains any bytes
    /// that were already buffered past the header block, then continues from the underlying stream.
    /// Disposing it disposes <c>owner</c> (the TLS connection + transport).
    /// </summary>
    internal sealed class Http1ContentStream : Stream
    {
        private byte[]? _prefix;
        private int _prefixPos;
        private readonly Stream _inner;
        private readonly IDisposable? _owner;
        private readonly bool _keepAlive;
        private readonly Action<bool>? _onDisposed;
        private bool _disposed;

        private readonly bool _chunked;
        private readonly bool _hasLength;
        private long _remaining;       // Content-Length bytes left, or -1 for until-close

        // chunked state
        private bool _chunkedDone;
        private long _chunkRemaining;
        private bool _sawAnyChunk;

        /// <param name="prefix">Bytes already read past the header block (drained before reading from <paramref name="inner"/>).</param>
        /// <param name="inner">The underlying (plaintext) stream the body continues from.</param>
        /// <param name="chunked">Whether the body is Transfer-Encoding: chunked.</param>
        /// <param name="contentLength">The Content-Length, or null when chunked / read-until-close.</param>
        /// <param name="owner">Disposed on dispose when <paramref name="onDisposed"/> is null (the TLS connection + transport).</param>
        /// <param name="keepAlive">Whether the connection could be reused once the body is fully drained.</param>
        /// <param name="onDisposed">
        /// When set, invoked on dispose with whether the connection is reusable (keep-alive AND fully drained),
        /// instead of disposing <paramref name="owner"/> directly. When null, <paramref name="owner"/> is disposed.
        /// </param>
        public Http1ContentStream(byte[] prefix, Stream inner, bool chunked, long? contentLength, IDisposable? owner,
            bool keepAlive = false, Action<bool>? onDisposed = null)
        {
            _prefix = prefix.Length > 0 ? prefix : null;
            _inner = inner;
            _owner = owner;
            _keepAlive = keepAlive;
            _onDisposed = onDisposed;
            _chunked = chunked;
            if (chunked)
            {
                _hasLength = false;
                _remaining = 0;
            }
            else if (contentLength.HasValue)
            {
                _hasLength = true;
                _remaining = contentLength.Value;
            }
            else
            {
                _hasLength = false;
                _remaining = -1; // until close
            }
        }

        private int ReadRaw(byte[] buffer, int offset, int count)
        {
            if (count <= 0) return 0;
            if (_prefix != null)
            {
                int n = Math.Min(count, _prefix.Length - _prefixPos);
                Array.Copy(_prefix, _prefixPos, buffer, offset, n);
                _prefixPos += n;
                if (_prefixPos >= _prefix.Length) _prefix = null;
                return n;
            }
            return _inner.Read(buffer, offset, count);
        }

        private int ReadRawByte()
        {
            if (_prefix != null)
            {
                byte b = _prefix[_prefixPos++];
                if (_prefixPos >= _prefix.Length) _prefix = null;
                return b;
            }
            Span<byte> one = stackalloc byte[1];
            return _inner.Read(one) == 1 ? one[0] : -1;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (buffer is null) throw new ArgumentNullException(nameof(buffer));
            if ((uint)offset > (uint)buffer.Length || (uint)count > (uint)(buffer.Length - offset))
                throw new ArgumentOutOfRangeException();

            if (_chunked) return ReadChunked(buffer, offset, count);
            if (_hasLength)
            {
                if (_remaining <= 0) return 0;
                int toRead = (int)Math.Min(count, _remaining);
                int n = ReadRaw(buffer, offset, toRead);
                if (n > 0) _remaining -= n;
                return n;
            }
            return ReadRaw(buffer, offset, count); // until close
        }

        private int ReadChunked(byte[] buffer, int offset, int count)
        {
            if (_chunkedDone) return 0;
            while (_chunkRemaining == 0)
            {
                if (_sawAnyChunk) ReadLineRaw();   // consume CRLF after previous chunk data
                long size = ReadChunkSize();
                _sawAnyChunk = true;
                if (size == 0)
                {
                    while (ReadLineRaw().Length > 0) { /* skip trailers */ }
                    _chunkedDone = true;
                    return 0;
                }
                _chunkRemaining = size;
            }
            int toRead = (int)Math.Min(count, _chunkRemaining);
            int read = ReadRaw(buffer, offset, toRead);
            if (read <= 0) { _chunkedDone = true; return 0; }
            _chunkRemaining -= read;
            return read;
        }

        private long ReadChunkSize()
        {
            string line = ReadLineRaw();
            int semi = line.IndexOf(';');
            if (semi >= 0) line = line.Substring(0, semi);
            line = line.Trim();
            return Convert.ToInt64(line, 16);
        }

        private string ReadLineRaw()
        {
            var sb = new System.Text.StringBuilder();
            while (true)
            {
                int b = ReadRawByte();
                if (b < 0 || b == '\n') break;
                if (b != '\r') sb.Append((char)b);
            }
            return sb.ToString();
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => Task.Run(() => Read(buffer, offset, count), cancellationToken);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => new(Task.Run(() =>
            {
                if (System.Runtime.InteropServices.MemoryMarshal.TryGetArray<byte>(buffer, out var seg))
                    return Read(seg.Array!, seg.Offset, seg.Count);
                byte[] tmp = new byte[buffer.Length];
                int n = Read(tmp, 0, tmp.Length);
                tmp.AsSpan(0, n).CopyTo(buffer.Span);
                return n;
            }, cancellationToken));

        public override bool CanRead => true;
        public override bool CanWrite => false;
        public override bool CanSeek => false;
        public override void Flush() { }
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        /// <summary>True once the body has been fully consumed (so the connection's read position is at the next response).</summary>
        private bool Drained => _chunked ? _chunkedDone : (_hasLength ? _remaining <= 0 : false);

        /// <summary>
        /// Returns and clears any bytes that were buffered past this body (the start of the next pipelined/keep-alive
        /// response that the header read over-read). The owning connection seeds these for its next request.
        /// </summary>
        public byte[] TakeUnconsumedPrefix()
        {
            if (_prefix == null || _prefixPos >= _prefix.Length) return Array.Empty<byte>();
            byte[] rest = _prefix[_prefixPos..];
            _prefix = null;
            return rest;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && !_disposed)
            {
                _disposed = true;
                if (_onDisposed != null)
                {
                    try { _onDisposed(_keepAlive && Drained); } catch { /* best effort */ }
                }
                else
                {
                    try { _owner?.Dispose(); } catch { /* best effort */ }
                }
            }
            base.Dispose(disposing);
        }
    }
}
