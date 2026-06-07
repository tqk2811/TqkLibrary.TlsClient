using System;
using System.IO;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace TqkLibrary.TlsClient.Tests
{
    /// <summary>In-memory full-duplex stream: reads canned bytes, captures everything written.</summary>
    internal sealed class DuplexTestStream : Stream
    {
        private readonly MemoryStream _read;
        public MemoryStream Written { get; } = new();

        public DuplexTestStream(byte[] cannedResponse) => _read = new MemoryStream(cannedResponse);

        public override int Read(byte[] buffer, int offset, int count) => _read.Read(buffer, offset, count);
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => Task.FromResult(_read.Read(buffer, offset, count));

        public override void Write(byte[] buffer, int offset, int count) => Written.Write(buffer, offset, count);
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            Written.Write(buffer, offset, count);
            return Task.CompletedTask;
        }

        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    internal sealed class FlagDisposable : IDisposable
    {
        public bool Disposed { get; private set; }
        public void Dispose() => Disposed = true;
    }

    /// <summary>
    /// Full-duplex stream whose read side is driven by <see cref="Feed"/> calls over time (so a test can act as
    /// an HTTP/2 server that responds only after the client has sent its requests). Writes are captured.
    /// </summary>
    internal sealed class ProgrammableDuplexStream : Stream
    {
        private readonly Channel<byte[]> _incoming = Channel.CreateUnbounded<byte[]>();
        private readonly MemoryStream _written = new();
        private readonly object _writeLock = new();
        private byte[] _current = Array.Empty<byte>();
        private int _pos;

        public void Feed(byte[] bytes) => _incoming.Writer.TryWrite(bytes);
        public void FeedComplete() => _incoming.Writer.TryComplete();

        public byte[] WrittenSnapshot()
        {
            lock (_writeLock) return _written.ToArray();
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            while (_pos >= _current.Length)
            {
                if (!await _incoming.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false)) return 0;
                if (_incoming.Reader.TryRead(out byte[]? next)) { _current = next; _pos = 0; }
            }
            int n = Math.Min(buffer.Length, _current.Length - _pos);
            _current.AsSpan(_pos, n).CopyTo(buffer.Span);
            _pos += n;
            return n;
        }

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override void Write(byte[] buffer, int offset, int count)
        {
            lock (_writeLock) _written.Write(buffer, offset, count);
        }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            lock (_writeLock) _written.Write(buffer, offset, count);
            return Task.CompletedTask;
        }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            lock (_writeLock) _written.Write(buffer.Span);
            return ValueTask.CompletedTask;
        }

        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing) _incoming.Writer.TryComplete();
            base.Dispose(disposing);
        }
    }
}
