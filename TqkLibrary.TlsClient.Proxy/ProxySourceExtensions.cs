using System;
using System.IO;
using TqkLibrary.Proxy.Interfaces;

namespace TqkLibrary.TlsClient.Proxy
{
    /// <summary>
    /// Routes a <see cref="TlsImpersonateHandler"/>'s transport through a TqkLibrary.Proxy
    /// <see cref="IProxySource"/> (direct, SOCKS4/5, or HTTP CONNECT), so impersonated requests can go via a proxy.
    /// </summary>
    public static class ProxySourceExtensions
    {
        /// <summary>Use <paramref name="proxySource"/> to open each impersonated connection's transport.</summary>
        public static TlsImpersonateHandler UseProxySource(this TlsImpersonateHandler handler, IProxySource proxySource)
        {
            if (handler is null) throw new ArgumentNullException(nameof(handler));
            if (proxySource is null) throw new ArgumentNullException(nameof(proxySource));

            handler.TransportFactory = async (endPoint, ct) =>
            {
                IConnectSource connect = await proxySource.GetConnectSourceAsync(Guid.NewGuid(), ct).ConfigureAwait(false);
                try
                {
                    Uri target = new UriBuilder("https", endPoint.Host, endPoint.Port).Uri;
                    await connect.ConnectAsync(target, ct).ConfigureAwait(false);
                    Stream inner = await connect.GetStreamAsync(ct).ConfigureAwait(false);
                    return new ConnectSourceStream(inner, connect);
                }
                catch
                {
                    connect.Dispose();
                    throw;
                }
            };
            return handler;
        }
    }
}
