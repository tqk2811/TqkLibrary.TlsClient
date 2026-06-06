using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.TlsClient.Native.Models;

namespace TqkLibrary.TlsClient.Native
{
    /// <summary>
    /// A TLS stream that impersonates a browser fingerprint, modeled after <see cref="System.Net.Security.SslStream"/>:
    /// wrap a raw (unencrypted) inner <see cref="Stream"/>, call <see cref="AuthenticateAsClientAsync"/>,
    /// and from then on this stream carries plaintext. The TLS record layer / ClientHello shaping is
    /// performed by the native uTLS codec; this class only marshals plaintext and the inner ciphertext stream.
    /// </summary>
    public sealed unsafe class ImpersonatedTlsStream : Stream
    {
        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        private readonly Stream _inner;
        private readonly bool _ownsInner;
        private TransportBridge? _bridge;
        private long _id;
        private bool _authenticated;
        private string _alpn = string.Empty;

        /// <param name="inner">Raw, unencrypted transport stream (e.g. <c>TcpClient.GetStream()</c> or <c>IConnectSource.GetStreamAsync()</c>).</param>
        /// <param name="ownsInner">If true, disposing this stream disposes <paramref name="inner"/>.</param>
        public ImpersonatedTlsStream(Stream inner, bool ownsInner = false)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _ownsInner = ownsInner;
        }

        /// <summary>The ALPN protocol negotiated during the handshake (e.g. "h2" or "http/1.1").</summary>
        public string NegotiatedAlpn => _alpn;

        public bool IsAuthenticated => _authenticated;

        /// <summary>Run the impersonated TLS handshake. Blocks on transport I/O, so it runs on a thread-pool thread.</summary>
        public Task AuthenticateAsClientAsync(TlsCodecOptions options, CancellationToken cancellationToken = default)
            => Task.Run(() => AuthenticateAsClient(options), cancellationToken);

        public void AuthenticateAsClient(TlsCodecOptions options)
        {
            if (options is null) throw new ArgumentNullException(nameof(options));
            if (_authenticated) throw new InvalidOperationException("Already authenticated.");

            _bridge = new TransportBridge(_inner, _ownsInner);

            string json = JsonSerializer.Serialize(options, JsonOpts);
            byte[] jsonUtf8 = Encoding.UTF8.GetBytes(json);
            Array.Resize(ref jsonUtf8, jsonUtf8.Length + 1); // NUL-terminate for the C string

            fixed (byte* pJson = jsonUtf8)
            {
                _id = NativeMethods.TlsNew(
                    pJson,
                    TransportBridge.ReadPtr,
                    TransportBridge.WritePtr,
                    TransportBridge.ClosePtr,
                    _bridge.Context);
            }
            if (_id <= 0)
                throw new IOException("Native TlsNew failed (invalid options?).");

            byte* err = NativeMethods.TlsHandshake(_id);
            if (err != null)
            {
                string msg = Marshal.PtrToStringUTF8((IntPtr)err) ?? "unknown error";
                NativeMethods.TlsFreeString(err);
                throw new IOException("TLS handshake failed: " + msg);
            }

            byte* alpn = NativeMethods.TlsGetAlpn(_id);
            if (alpn != null)
            {
                _alpn = Marshal.PtrToStringUTF8((IntPtr)alpn) ?? string.Empty;
                NativeMethods.TlsFreeString(alpn);
            }
            _authenticated = true;
        }

        private void EnsureAuth()
        {
            if (!_authenticated) throw new InvalidOperationException("Stream is not authenticated. Call AuthenticateAsClient first.");
        }

        public override int Read(byte[] buffer, int offset, int count)
            => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            EnsureAuth();
            if (buffer.IsEmpty) return 0;
            fixed (byte* p = buffer)
            {
                int n = NativeMethods.TlsRead(_id, p, buffer.Length);
                if (n < 0) throw new IOException("Native TlsRead failed.");
                return n; // 0 == EOF
            }
        }

        public override void Write(byte[] buffer, int offset, int count)
            => Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            EnsureAuth();
            if (buffer.IsEmpty) return;
            fixed (byte* p = buffer)
            {
                int total = 0;
                while (total < buffer.Length)
                {
                    int n = NativeMethods.TlsWrite(_id, p + total, buffer.Length - total);
                    if (n <= 0) throw new IOException("Native TlsWrite failed.");
                    total += n;
                }
            }
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => Task.Run(() => Read(buffer, offset, count), cancellationToken);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => new(Task.Run(() => ReadMemory(buffer), cancellationToken));

        private int ReadMemory(Memory<byte> buffer) => Read(buffer.Span);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => Task.Run(() => Write(buffer, offset, count), cancellationToken);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => new(Task.Run(() => WriteMemory(buffer), cancellationToken));

        private void WriteMemory(ReadOnlyMemory<byte> buffer) => Write(buffer.Span);

        public override void Flush() => _inner.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (_id > 0)
            {
                NativeMethods.TlsClose(_id); // closes the native conn; CloseCb disposes inner if owned
                _id = 0;
            }
            else if (_ownsInner)
            {
                // Handshake never ran, so CloseCb won't fire — dispose the inner stream ourselves.
                try { _inner.Dispose(); } catch { /* best effort */ }
            }
            _bridge?.Dispose();
            _bridge = null;
            base.Dispose(disposing);
        }
    }
}
