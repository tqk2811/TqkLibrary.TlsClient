using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.TlsClient.Capture
{
    /// <summary>
    /// A pass-through <see cref="Stream"/> that tees the bytes it reads, sniffing the first TLS ClientHello as
    /// it flows by. Wrap the stream your proxy reads the client's bytes from (client→server, pre-encryption);
    /// once a full ClientHello has gone through, <see cref="CapturedClientHello"/> is populated. Reads and
    /// writes otherwise behave exactly like the inner stream, so relaying is unaffected.
    /// </summary>
    public sealed class ClientHelloCaptureStream : Stream
    {
        private const int MaxSniffBytes = 64 * 1024; // a ClientHello fits well under this; stop sniffing past it

        private readonly Stream _inner;
        private readonly bool _ownsInner;
        private readonly MemoryStream _sniffed = new();
        private bool _captureFinished;
        private byte[]? _clientHello;

        public ClientHelloCaptureStream(Stream inner, bool ownsInner = false)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _ownsInner = ownsInner;
        }

        /// <summary>The captured ClientHello TLS record, or null until a complete ClientHello has been read through.</summary>
        public byte[]? CapturedClientHello => _clientHello;

        /// <summary>True once a complete ClientHello has been captured.</summary>
        public bool Captured => _clientHello != null;

        private void Sniff(ReadOnlySpan<byte> data)
        {
            if (_captureFinished || data.Length == 0) return;
            _sniffed.Write(data);
            if (ClientHelloCapture.TryExtractClientHello(_sniffed.GetBuffer().AsSpan(0, (int)_sniffed.Length), out byte[] record))
            {
                _clientHello = record;
                _captureFinished = true;
                _sniffed.SetLength(0);
            }
            else if (_sniffed.Length > MaxSniffBytes)
            {
                _captureFinished = true; // give up: not a TLS ClientHello (or too fragmented)
                _sniffed.SetLength(0);
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = _inner.Read(buffer, offset, count);
            if (n > 0) Sniff(buffer.AsSpan(offset, n));
            return n;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int n = await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (n > 0) Sniff(buffer.Span.Slice(0, n));
            return n;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _inner.WriteAsync(buffer, offset, count, cancellationToken);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => _inner.WriteAsync(buffer, cancellationToken);

        public override void Flush() => _inner.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

        public override bool CanRead => _inner.CanRead;
        public override bool CanWrite => _inner.CanWrite;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _sniffed.Dispose();
                if (_ownsInner) _inner.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
