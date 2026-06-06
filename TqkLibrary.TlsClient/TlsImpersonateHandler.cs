using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.TlsClient.Http1;
using TqkLibrary.TlsClient.Http2;
using TqkLibrary.TlsClient.Http2.Models;
using TqkLibrary.TlsClient.Native;
using TqkLibrary.TlsClient.Native.Models;

namespace TqkLibrary.TlsClient
{
    /// <summary>
    /// Terminal <see cref="HttpMessageHandler"/> that performs requests over an impersonated TLS
    /// connection. The fingerprint (Chrome, captured ClientHello, ...) is configured here; the raw
    /// transport is produced by <see cref="TransportFactory"/> (default: a plain TCP socket), so the
    /// caller can plug in a proxy by returning its own <see cref="Stream"/>.
    ///
    /// Place DelegatingHandlers (redirect/cookie) ABOVE this handler in the pipeline.
    /// HTTP/2 is not implemented yet (Phase 3); keep <see cref="AlpnProtocols"/> at http/1.1 for now.
    /// </summary>
    public sealed class TlsImpersonateHandler : HttpMessageHandler
    {
        /// <summary>Named preset, e.g. "chrome", "chrome_120", "firefox". Ignored if <see cref="RawClientHelloBase64"/> is set.</summary>
        public string? Profile { get; set; } = "chrome";

        /// <summary>JA3 string (native side not implemented yet).</summary>
        public string? Ja3 { get; set; }

        /// <summary>Captured ClientHello (full TLS record), base64. Highest-priority fingerprint source.</summary>
        public string? RawClientHelloBase64 { get; set; }

        /// <summary>ALPN protocols to offer (default Chrome-like h2 then http/1.1).</summary>
        public IReadOnlyList<string> AlpnProtocols { get; set; } = new[] { "h2", "http/1.1" };

        /// <summary>HTTP/2 fingerprint used when h2 is negotiated (SETTINGS/WINDOW_UPDATE/priorities/pseudo-order).</summary>
        public Http2FingerprintConfig Http2Fingerprint { get; set; } = Http2FingerprintConfig.Chrome();

        /// <summary>Skip server certificate validation. Note: the native verifier does not do AIA chasing.</summary>
        public bool InsecureSkipVerify { get; set; }

        /// <summary>Produces a raw (unencrypted) connected transport stream for the target endpoint.</summary>
        public Func<DnsEndPoint, CancellationToken, Task<Stream>> TransportFactory { get; set; } = DefaultTransportAsync;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Uri uri = request.RequestUri ?? throw new InvalidOperationException("RequestUri is null.");
            if (!uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                throw new NotSupportedException($"Only https is supported, got '{uri.Scheme}'.");

            string host = uri.IdnHost;
            var endPoint = new DnsEndPoint(host, uri.Port);

            Stream transport = await TransportFactory(endPoint, cancellationToken).ConfigureAwait(false);

            ImpersonatedTlsStream tls;
            try
            {
                tls = new ImpersonatedTlsStream(transport, ownsInner: true);
                await tls.AuthenticateAsClientAsync(new TlsCodecOptions
                {
                    ServerName = host,
                    Profile = Profile,
                    Ja3 = Ja3,
                    RawClientHelloBase64 = RawClientHelloBase64,
                    Alpn = AlpnProtocols.ToArray(),
                    InsecureSkipVerify = InsecureSkipVerify,
                }, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                transport.Dispose();
                throw;
            }

            try
            {
                if (string.Equals(tls.NegotiatedAlpn, "h2", StringComparison.Ordinal))
                {
                    var http2 = new Http2Connection(tls, Http2Fingerprint);
                    HttpResponseMessage response = await http2.SendAsync(request, cancellationToken).ConfigureAwait(false);
                    tls.Dispose(); // the h2 body is fully buffered into the response, so the connection can close
                    return response;
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
    }
}
