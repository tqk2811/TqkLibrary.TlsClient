using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using TqkLibrary.TlsClient.Capture;
using TqkLibrary.TlsClient.Http2.Models;

namespace TqkLibrary.TlsClient.Profiles
{
    /// <summary>
    /// A complete browser impersonation profile: the TLS ClientHello source (named preset, JA3, or a
    /// captured ClientHello), the ALPN to offer, and the HTTP/2 fingerprint. Capture these from a real
    /// browser via a proxy and persist them with <see cref="ToJson"/> / <see cref="FromJson"/>.
    /// </summary>
    public sealed class TlsProfile
    {
        /// <summary>Named uTLS preset (e.g. "chrome", "chrome_120", "firefox"). Ignored if <see cref="RawClientHelloBase64"/> is set.</summary>
        public string? Name { get; set; }

        /// <summary>JA3 string (native side not implemented yet).</summary>
        public string? Ja3 { get; set; }

        /// <summary>Captured ClientHello (full TLS record), base64. Highest-priority TLS fingerprint source.</summary>
        public string? RawClientHelloBase64 { get; set; }

        /// <summary>ALPN protocols to offer in the ClientHello.</summary>
        public IList<string> Alpn { get; set; } = new List<string> { "h2", "http/1.1" };

        /// <summary>HTTP/2 fingerprint (SETTINGS/WINDOW_UPDATE/priorities/pseudo-order).</summary>
        public Http2FingerprintConfig Http2 { get; set; } = Http2FingerprintConfig.Chrome();

        /// <summary>A recent-Chrome profile (TLS preset + Chrome h2 fingerprint).</summary>
        public static TlsProfile Chrome() => new() { Name = "chrome", Http2 = Http2FingerprintConfig.Chrome() };

        /// <summary>A profile from a named uTLS preset.</summary>
        public static TlsProfile FromName(string name) => new() { Name = name };

        /// <summary>A profile from a JA3 string.</summary>
        public static TlsProfile FromJa3(string ja3) => new() { Ja3 = ja3 };

        /// <summary>A profile from a full captured ClientHello TLS record (e.g. sniffed by your proxy).</summary>
        public static TlsProfile FromCapturedClientHello(ReadOnlySpan<byte> rawClientHelloRecord)
            => new() { RawClientHelloBase64 = Convert.ToBase64String(rawClientHelloRecord) };

        /// <summary>
        /// Builds a profile from the raw, pre-encryption client→server bytes captured off the wire (what your
        /// proxy reads before the TLS session starts). The leading TLS ClientHello record is extracted and its
        /// advertised ALPN is carried into the profile. Throws when no complete ClientHello is present.
        /// </summary>
        public static TlsProfile FromCapturedHandshake(ReadOnlySpan<byte> rawClientBytes)
        {
            if (!ClientHelloCapture.TryExtractClientHello(rawClientBytes, out byte[] record))
                throw new ArgumentException("No complete TLS ClientHello record found at the start of the captured bytes.", nameof(rawClientBytes));

            var profile = FromCapturedClientHello(record);
            if (ClientHelloCapture.TryExtractAlpn(record, out List<string> alpn))
                profile.Alpn = alpn;
            return profile;
        }

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        public string ToJson() => JsonSerializer.Serialize(this, JsonOptions);

        public static TlsProfile FromJson(string json)
            => JsonSerializer.Deserialize<TlsProfile>(json, JsonOptions) ?? throw new ArgumentException("Invalid profile JSON.", nameof(json));
    }
}
