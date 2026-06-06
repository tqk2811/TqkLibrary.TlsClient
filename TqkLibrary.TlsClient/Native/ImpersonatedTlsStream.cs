using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.TlsClient.Native.Helpers;
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

        /// <summary>The server certificate chain (leaf first), available after authentication.</summary>
        public X509Certificate2[]? PeerCertificates { get; private set; }

        /// <summary>
        /// Optional certificate validation callback (same shape as <see cref="SslStream"/>'s). When set, it
        /// decides whether to accept the server certificate (the chain is built with AIA + the OS trust store).
        /// When null, default validation runs unless <see cref="TlsCodecOptions.InsecureSkipVerify"/> is set.
        /// </summary>
        public RemoteCertificateValidationCallback? CertificateValidationCallback { get; set; }

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

            PeerCertificates = FetchPeerCertificates();
            if (!options.InsecureSkipVerify)
                ValidateServerCertificate(options.ServerName ?? string.Empty);

            _authenticated = true;
        }

        private X509Certificate2[] FetchPeerCertificates()
        {
            byte* p = NativeMethods.TlsGetPeerCertificates(_id);
            if (p == null) return Array.Empty<X509Certificate2>();
            string base64;
            try { base64 = Marshal.PtrToStringUTF8((IntPtr)p) ?? string.Empty; }
            finally { NativeMethods.TlsFreeString(p); }
            if (base64.Length == 0) return Array.Empty<X509Certificate2>();

            byte[] blob = Convert.FromBase64String(base64);
            var certs = new List<X509Certificate2>();
            int o = 0;
            while (o + 4 <= blob.Length)
            {
                int len = (blob[o] << 24) | (blob[o + 1] << 16) | (blob[o + 2] << 8) | blob[o + 3];
                o += 4;
                if (len < 0 || o + len > blob.Length) break;
                certs.Add(new X509Certificate2(blob.AsSpan(o, len).ToArray()));
                o += len;
            }
            return certs.ToArray();
        }

        private void ValidateServerCertificate(string host)
        {
            if (PeerCertificates is null || PeerCertificates.Length == 0)
                throw new AuthenticationException("The server presented no certificate.");

            X509Certificate2 leaf = PeerCertificates[0];
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            for (int i = 1; i < PeerCertificates.Length; i++)
                chain.ChainPolicy.ExtraStore.Add(PeerCertificates[i]);

            bool chainOk = chain.Build(leaf);   // builds against the OS trust store, chasing AIA intermediates
            bool nameOk = HostnameVerifier.Matches(leaf, host);

            SslPolicyErrors errors = SslPolicyErrors.None;
            if (!chainOk) errors |= SslPolicyErrors.RemoteCertificateChainErrors;
            if (!nameOk) errors |= SslPolicyErrors.RemoteCertificateNameMismatch;

            RemoteCertificateValidationCallback? callback = CertificateValidationCallback;
            if (callback != null)
            {
                if (!callback(this, leaf, chain, errors))
                    throw new AuthenticationException("The certificate validation callback rejected the server certificate.");
            }
            else if (errors != SslPolicyErrors.None)
            {
                throw new AuthenticationException($"Server certificate validation failed: {errors}.");
            }
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
            if (PeerCertificates != null)
            {
                foreach (X509Certificate2 c in PeerCertificates) c.Dispose();
                PeerCertificates = null;
            }
            base.Dispose(disposing);
        }
    }
}
