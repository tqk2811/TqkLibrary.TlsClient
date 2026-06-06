using System;
using TqkLibrary.TlsClient.Http2;
using TqkLibrary.TlsClient.Native;

namespace TqkLibrary.TlsClient.Pooling
{
    /// <summary>A reusable TLS connection plus its negotiated protocol state, held by <see cref="TlsConnectionPool"/>.</summary>
    internal sealed class PooledConnection : IDisposable
    {
        public PooledConnection(ImpersonatedTlsStream tls, string alpn, Http2Connection? http2)
        {
            Tls = tls;
            Alpn = alpn;
            Http2 = http2;
        }

        public ImpersonatedTlsStream Tls { get; }
        public string Alpn { get; }

        /// <summary>The reusable HTTP/2 client when <see cref="Alpn"/> is "h2"; otherwise null.</summary>
        public Http2Connection? Http2 { get; }

        public void Dispose() => Tls.Dispose();
    }
}
