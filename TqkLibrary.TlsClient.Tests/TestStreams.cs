using System;
using System.IO;
using System.Threading;
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
}
