using System.Net.Http;
using TqkLibrary.TlsClient.Profiles;

namespace TqkLibrary.TlsClient
{
    /// <summary>Convenience factory methods for building an impersonating <see cref="HttpClient"/> from a <see cref="TlsProfile"/>.</summary>
    public static class TlsClientExtension
    {
        /// <summary>Create a terminal handler for this profile.</summary>
        public static TlsImpersonateHandler CreateHandler(this TlsProfile profile, bool insecureSkipVerify = false)
            => new(profile) { InsecureSkipVerify = insecureSkipVerify };

        /// <summary>
        /// Create an <see cref="HttpClient"/> that impersonates this profile. Optionally wrap the terminal
        /// handler with your own DelegatingHandler pipeline (e.g. redirect/cookie handlers) via <paramref name="pipeline"/>.
        /// </summary>
        public static HttpClient CreateHttpClient(this TlsProfile profile, bool insecureSkipVerify = false,
            System.Func<TlsImpersonateHandler, HttpMessageHandler>? pipeline = null)
        {
            TlsImpersonateHandler handler = profile.CreateHandler(insecureSkipVerify);
            HttpMessageHandler top = pipeline is null ? handler : pipeline(handler);
            return new HttpClient(top);
        }
    }
}
