using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.TlsClient.Http1;
using TqkLibrary.TlsClient.Http2;
using TqkLibrary.TlsClient.Native;
using TqkLibrary.TlsClient.Native.Models;
using TqkLibrary.TlsClient.Profiles;

namespace TqkLibrary.TlsClient
{
    /// <summary>
    /// Terminal <see cref="HttpMessageHandler"/> that performs requests over an impersonated TLS + HTTP
    /// connection. The browser fingerprint is described by a <see cref="TlsProfile"/>; the raw transport is
    /// produced by <see cref="TransportFactory"/> (default: a plain TCP socket), so a proxy can be plugged in
    /// by returning its own <see cref="Stream"/>. Dispatches to HTTP/2 or HTTP/1.1 based on negotiated ALPN.
    ///
    /// Place DelegatingHandlers (redirect/cookie) ABOVE this handler in the pipeline.
    /// </summary>
    public sealed class TlsImpersonateHandler : HttpMessageHandler
    {
        public TlsImpersonateHandler() : this(TlsProfile.Chrome()) { }

        public TlsImpersonateHandler(TlsProfile profile) => Profile = profile ?? throw new ArgumentNullException(nameof(profile));

        /// <summary>The browser impersonation profile (TLS + HTTP/2 fingerprint).</summary>
        public TlsProfile Profile { get; set; }

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
                    Profile = Profile.Name,
                    Ja3 = Profile.Ja3,
                    RawClientHelloBase64 = Profile.RawClientHelloBase64,
                    Alpn = Profile.Alpn.ToArray(),
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
                    var http2 = new Http2Connection(tls, Profile.Http2);
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
