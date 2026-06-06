using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.TlsClient.Http1;
using TqkLibrary.TlsClient.Http2;
using TqkLibrary.TlsClient.Native;
using TqkLibrary.TlsClient.Native.Models;
using TqkLibrary.TlsClient.Pooling;
using TqkLibrary.TlsClient.Profiles;

namespace TqkLibrary.TlsClient
{
    /// <summary>
    /// Terminal <see cref="HttpMessageHandler"/> that performs requests over an impersonated TLS + HTTP
    /// connection. The browser fingerprint is described by a <see cref="TlsProfile"/>; the raw transport is
    /// produced by <see cref="TransportFactory"/> (default: a plain TCP socket), so a proxy can be plugged in
    /// by returning its own <see cref="Stream"/>. Dispatches to HTTP/2 or HTTP/1.1 based on negotiated ALPN.
    ///
    /// HTTP/2 connections are pooled and reused for sequential, body-less requests to the same host.
    /// Place DelegatingHandlers (redirect/cookie) ABOVE this handler in the pipeline.
    /// </summary>
    public sealed class TlsImpersonateHandler : HttpMessageHandler
    {
        private readonly TlsConnectionPool _pool = new();
        private int _connectionsCreated;

        public TlsImpersonateHandler() : this(TlsProfile.Chrome()) { }

        public TlsImpersonateHandler(TlsProfile profile) => Profile = profile ?? throw new ArgumentNullException(nameof(profile));

        /// <summary>The browser impersonation profile (TLS + HTTP/2 fingerprint).</summary>
        public TlsProfile Profile { get; set; }

        /// <summary>Skip server certificate validation entirely.</summary>
        public bool InsecureSkipVerify { get; set; }

        /// <summary>
        /// Optional server certificate validation callback (same shape as <see cref="SslStream"/>'s). When null,
        /// default validation runs (chain built with AIA + the OS trust store, plus a hostname check) unless
        /// <see cref="InsecureSkipVerify"/> is set.
        /// </summary>
        public RemoteCertificateValidationCallback? ServerCertificateValidationCallback { get; set; }

        /// <summary>Reuse pooled HTTP/2 connections for sequential, body-less requests to the same host.</summary>
        public bool EnableConnectionReuse { get; set; } = true;

        /// <summary>
        /// Transparently decompress responses whose Content-Encoding is gzip/deflate/br (when the caller
        /// advertised it via Accept-Encoding). Note: Accept-Encoding is never added automatically, so it
        /// stays under the caller's control for fingerprint fidelity.
        /// </summary>
        public DecompressionMethods AutomaticDecompression { get; set; } = DecompressionMethods.All;

        /// <summary>Number of physical TLS connections this handler has opened (for diagnostics/tests).</summary>
        public int ConnectionsCreated => _connectionsCreated;

        /// <summary>Produces a raw (unencrypted) connected transport stream for the target endpoint.</summary>
        public Func<DnsEndPoint, CancellationToken, Task<Stream>> TransportFactory { get; set; } = DefaultTransportAsync;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            HttpResponseMessage response = await SendCoreAsync(request, cancellationToken).ConfigureAwait(false);
            ApplyDecompression(response);
            return response;
        }

        private void ApplyDecompression(HttpResponseMessage response)
        {
            if (AutomaticDecompression == DecompressionMethods.None) return;
            var contentEncoding = response.Content.Headers.ContentEncoding;
            if (contentEncoding.Count == 0) return;

            string encoding = contentEncoding.Last().ToLowerInvariant();
            Stream source = response.Content.ReadAsStream();
            Stream? decompressed = encoding switch
            {
                "gzip" when (AutomaticDecompression & DecompressionMethods.GZip) != 0 => new GZipStream(source, CompressionMode.Decompress),
                "br" when (AutomaticDecompression & DecompressionMethods.Brotli) != 0 => new BrotliStream(source, CompressionMode.Decompress),
                "deflate" when (AutomaticDecompression & DecompressionMethods.Deflate) != 0 => new ZLibStream(source, CompressionMode.Decompress),
                _ => null,
            };
            if (decompressed is null) return;

            var newContent = new StreamContent(decompressed);
            foreach (var header in response.Content.Headers)
            {
                if (string.Equals(header.Key, "Content-Encoding", StringComparison.OrdinalIgnoreCase)) continue;
                if (string.Equals(header.Key, "Content-Length", StringComparison.OrdinalIgnoreCase)) continue;
                newContent.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
            response.Content = newContent;
        }

        private async Task<HttpResponseMessage> SendCoreAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Uri uri = request.RequestUri ?? throw new InvalidOperationException("RequestUri is null.");
            if (!uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                throw new NotSupportedException($"Only https is supported, got '{uri.Scheme}'.");

            string host = uri.IdnHost;
            int port = uri.Port;
            string key = host + ":" + port;

            // Reuse a pooled h2 connection for sequential, body-less requests (safe to retry on a stale one).
            if (EnableConnectionReuse && request.Content is null)
            {
                for (PooledConnection? rented = _pool.Rent(key); rented is not null; rented = _pool.Rent(key))
                {
                    if (rented.Http2 is null)
                    {
                        rented.Dispose();
                        continue;
                    }
                    try
                    {
                        return await SendOverHttp2Async(rented, key, request, cancellationToken).ConfigureAwait(false);
                    }
                    catch (IOException)
                    {
                        rented.Dispose(); // stale connection — try another idle one, then a fresh connection
                    }
                    catch
                    {
                        rented.Dispose();
                        throw;
                    }
                }
            }

            (ImpersonatedTlsStream tls, string alpn) = await ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
            try
            {
                if (string.Equals(alpn, "h2", StringComparison.Ordinal))
                {
                    var pooled = new PooledConnection(tls, alpn, new Http2Connection(tls, Profile.Http2));
                    return await SendOverHttp2Async(pooled, key, request, cancellationToken).ConfigureAwait(false);
                }

                // HTTP/1.1: the response body streams from tls, so the content owns the connection's lifetime.
                return await new Http1Connection(tls, owner: tls).SendAsync(request, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                tls.Dispose();
                throw;
            }
        }

        private async Task<HttpResponseMessage> SendOverHttp2Async(PooledConnection pooled, string key, HttpRequestMessage request, CancellationToken ct)
        {
            Http2Connection http2 = pooled.Http2!;
            http2.OnResponseDisposed = reusable =>
            {
                if (reusable && EnableConnectionReuse) _pool.Return(key, pooled);
                else pooled.Dispose();
            };
            return await http2.SendAsync(request, ct).ConfigureAwait(false);
        }

        private async Task<(ImpersonatedTlsStream Tls, string Alpn)> ConnectAsync(string host, int port, CancellationToken ct)
        {
            Stream transport = await TransportFactory(new DnsEndPoint(host, port), ct).ConfigureAwait(false);
            try
            {
                var tls = new ImpersonatedTlsStream(transport, ownsInner: true)
                {
                    CertificateValidationCallback = ServerCertificateValidationCallback,
                };
                await tls.AuthenticateAsClientAsync(new TlsCodecOptions
                {
                    ServerName = host,
                    Profile = Profile.Name,
                    Ja3 = Profile.Ja3,
                    RawClientHelloBase64 = Profile.RawClientHelloBase64,
                    Alpn = Profile.Alpn.ToArray(),
                    InsecureSkipVerify = InsecureSkipVerify,
                }, ct).ConfigureAwait(false);
                Interlocked.Increment(ref _connectionsCreated);
                return (tls, tls.NegotiatedAlpn);
            }
            catch
            {
                transport.Dispose();
                throw;
            }
        }

        private static async Task<Stream> DefaultTransportAsync(DnsEndPoint endPoint, CancellationToken cancellationToken)
        {
            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(endPoint, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
            return new NetworkStream(socket, ownsSocket: true);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _pool.Dispose();
            base.Dispose(disposing);
        }
    }
}
