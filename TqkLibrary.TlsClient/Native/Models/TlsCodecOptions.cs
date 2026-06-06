namespace TqkLibrary.TlsClient.Native.Models
{
    /// <summary>
    /// Describes how the native uTLS codec should shape the ClientHello.
    /// Serialized to JSON (camelCase) and passed to the native <c>TlsNew</c>.
    /// Exactly one fingerprint source is used, in priority order:
    /// <see cref="RawClientHelloBase64"/> &gt; <see cref="Profile"/> &gt; <see cref="Ja3"/>.
    /// </summary>
    public sealed class TlsCodecOptions
    {
        /// <summary>SNI / server name for the handshake.</summary>
        public string? ServerName { get; set; }

        /// <summary>Named preset, e.g. "chrome", "chrome_120", "firefox", "safari", "ios", "edge".</summary>
        public string? Profile { get; set; }

        /// <summary>JA3 string (not implemented yet by the native side).</summary>
        public string? Ja3 { get; set; }

        /// <summary>Full captured TLS ClientHello record (with record header), base64-encoded.</summary>
        public string? RawClientHelloBase64 { get; set; }

        /// <summary>ALPN protocols to offer, e.g. ["h2","http/1.1"]. Overrides the preset's ALPN.</summary>
        public string[]? Alpn { get; set; }

        /// <summary>Skip server certificate validation (caller's responsibility otherwise).</summary>
        public bool InsecureSkipVerify { get; set; }
    }
}
