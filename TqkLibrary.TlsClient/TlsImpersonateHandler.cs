using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
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
    /// HTTP/2 connections are shared and multiplexed (many concurrent requests per connection, like a real
    /// browser); HTTP/1.1 connections are kept alive and pooled per host. Place DelegatingHandlers
    /// (redirect/cookie) ABOVE this handler in the pipeline.
    /// </summary>
    public sealed class TlsImpersonateHandler : HttpMessageHandler
    {
        private const int MaxConnectAttempts = 3;

        private readonly ConcurrentDictionary<string, Http2Connection> _h2 = new();
        private readonly ConcurrentDictionary<string, SemaphoreSlim> _connectGates = new();
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

        /// <summary>
        /// Reuse connections: multiplex HTTP/2 requests over a shared per-host connection, and keep HTTP/1.1
        /// connections alive in a per-host pool.
        /// </summary>
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

            for (int attempt = 1; attempt <= MaxConnectAttempts; attempt++)
            {
                // 1) Reuse a usable multiplexed HTTP/2 connection.
                if (EnableConnectionReuse && TryRentHttp2(key, out Http2Connection? h2))
                {
                    try { return await h2!.SendReservedAsync(request, cancellationToken).ConfigureAwait(false); }
                    catch (IOException) when (attempt < MaxConnectAttempts && !h2!.IsUsable) { RemoveH2(key, h2!); continue; }
                }

                // 2) Reuse a pooled keep-alive HTTP/1.1 connection.
                if (EnableConnectionReuse)
                {
                    PooledConnection? rented = RentHttp1(key);
                    if (rented is not null)
                    {
                        try { return await SendOverHttp1Async(rented, key, request, cancellationToken).ConfigureAwait(false); }
                        catch (IOException) when (attempt < MaxConnectAttempts) { rented.Dispose(); continue; }
                        catch { rented.Dispose(); throw; }
                    }
                }

                // 3) Establish a fresh connection (serialized per host so a burst doesn't open N connections).
                try { return await EstablishAndSendAsync(host, port, key, request, cancellationToken).ConfigureAwait(false); }
                catch (IOException) when (attempt < MaxConnectAttempts) { /* retry */ }
            }

            throw new IOException($"Could not complete the request to {key} after {MaxConnectAttempts} attempts.");
        }

        private async Task<HttpResponseMessage> EstablishAndSendAsync(string host, int port, string key, HttpRequestMessage request, CancellationToken ct)
        {
            SemaphoreSlim gate = _connectGates.GetOrAdd(key, static _ => new SemaphoreSlim(1, 1));
            await gate.WaitAsync(ct).ConfigureAwait(false);

            Http2Connection? h2 = null;
            PooledConnection? h1 = null;
            bool released = false;
            try
            {
                // Another caller may have just established a reusable h2 connection while we waited on the gate.
                if (EnableConnectionReuse && TryRentHttp2(key, out Http2Connection? existing))
                {
                    h2 = existing;
                }
                else
                {
                    (ImpersonatedTlsStream tls, string alpn) = await ConnectAsync(host, port, ct).ConfigureAwait(false);
                    if (string.Equals(alpn, "h2", StringComparison.Ordinal))
                    {
                        h2 = new Http2Connection(tls, Profile.Http2);
                        h2.TryBeginStream(); // reserve our slot on the fresh connection
                        if (EnableConnectionReuse) _h2[key] = h2;
                    }
                    else
                    {
                        h1 = new PooledConnection(tls, alpn) { Http1 = new Http1Connection(tls, owner: tls) };
                    }
                }

                gate.Release();
                released = true;

                if (h2 is not null)
                {
                    try { return await h2.SendReservedAsync(request, ct).ConfigureAwait(false); }
                    catch { if (!EnableConnectionReuse) h2.Dispose(); throw; }
                }
                return await SendOverHttp1Async(h1!, key, request, ct).ConfigureAwait(false);
            }
            finally
            {
                if (!released) gate.Release();
            }
        }

        private async Task<HttpResponseMessage> SendOverHttp1Async(PooledConnection pooled, string key, HttpRequestMessage request, CancellationToken ct)
        {
            Http1Connection http1 = pooled.Http1!;
            http1.OnResponseDrained = reusable =>
            {
                if (reusable && EnableConnectionReuse) _pool.Return(key, pooled);
                else pooled.Dispose();
            };
            return await http1.SendAsync(request, ct).ConfigureAwait(false);
        }

        private bool TryRentHttp2(string key, out Http2Connection? conn)
        {
            conn = null;
            if (_h2.TryGetValue(key, out Http2Connection? c))
            {
                if (c.TryBeginStream()) { conn = c; return true; }
                if (!c.IsUsable) RemoveH2(key, c);
            }
            return false;
        }

        private PooledConnection? RentHttp1(string key)
        {
            for (PooledConnection? rented = _pool.Rent(key); rented is not null; rented = _pool.Rent(key))
            {
                if (rented.Http1 is not null) return rented;
                rented.Dispose();
            }
            return null;
        }

        private void RemoveH2(string key, Http2Connection conn)
        {
            _h2.TryRemove(new KeyValuePair<string, Http2Connection>(key, conn));
            conn.Dispose();
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
            if (disposing)
            {
                foreach (Http2Connection conn in _h2.Values) conn.Dispose();
                _h2.Clear();
                _pool.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
