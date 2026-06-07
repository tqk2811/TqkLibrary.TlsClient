using System;
using TqkLibrary.TlsClient.Http1;
using TqkLibrary.TlsClient.Native;

namespace TqkLibrary.TlsClient.Pooling
{
    /// <summary>A reusable keep-alive TLS connection plus its HTTP/1.1 state, held by <see cref="TlsConnectionPool"/>.</summary>
    internal sealed class PooledConnection : IDisposable
    {
        public PooledConnection(ImpersonatedTlsStream tls, string alpn)
        {
            Tls = tls;
            Alpn = alpn;
        }

        public ImpersonatedTlsStream Tls { get; }
        public string Alpn { get; }

        /// <summary>The reusable HTTP/1.1 client bound to this connection.</summary>
        public Http1Connection? Http1 { get; set; }

        public void Dispose() => Tls.Dispose();
    }
}
