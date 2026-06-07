using System;
using System.Collections.Generic;

namespace TqkLibrary.TlsClient.Capture
{
    /// <summary>
    /// Extracts a TLS ClientHello from the start of a captured, *pre-encryption* client→server byte stream
    /// (the bytes your proxy reads off the wire before the TLS session is established). The ClientHello carries
    /// the JA3/JA4 fingerprint, so this is what you turn into a profile via
    /// <see cref="Profiles.TlsProfile.FromCapturedHandshake"/>.
    ///
    /// Note: only the TLS handshake is in cleartext here. The HTTP/2 (Akamai) fingerprint lives inside the
    /// encrypted session, so capture that separately from the decrypted stream and load it with
    /// <see cref="Http2.Models.Http2FingerprintConfig.FromAkamai"/>.
    /// </summary>
    public static class ClientHelloCapture
    {
        private const byte HandshakeContentType = 0x16; // TLS record: handshake
        private const byte ClientHelloHandshakeType = 0x01;
        private const int AlpnExtensionType = 0x0010;

        /// <summary>
        /// Tries to read a complete ClientHello (one or more TLS handshake records) from the start of
        /// <paramref name="raw"/>. On success, <paramref name="clientHelloRecord"/> is the verbatim record
        /// bytes (suitable for <see cref="Profiles.TlsProfile.FromCapturedClientHello"/>); returns false when
        /// the bytes don't begin with a complete TLS handshake ClientHello.
        /// </summary>
        public static bool TryExtractClientHello(ReadOnlySpan<byte> raw, out byte[] clientHelloRecord)
        {
            clientHelloRecord = Array.Empty<byte>();
            int pos = 0;
            int handshakeNeeded = -1; // total handshake-message bytes required (4-byte header + body)
            int handshakeHave = 0;

            while (true)
            {
                if (pos + 5 > raw.Length) return false;             // incomplete record header
                if (raw[pos] != HandshakeContentType) return false; // not a TLS handshake record
                int fragLen = (raw[pos + 3] << 8) | raw[pos + 4];
                int fragStart = pos + 5;
                if (fragLen <= 0 || fragStart + fragLen > raw.Length) return false; // incomplete record fragment

                if (handshakeNeeded < 0)
                {
                    if (fragLen < 4) return false;
                    if (raw[fragStart] != ClientHelloHandshakeType) return false; // not a ClientHello
                    int hsLen = (raw[fragStart + 1] << 16) | (raw[fragStart + 2] << 8) | raw[fragStart + 3];
                    handshakeNeeded = 4 + hsLen;
                }

                handshakeHave += fragLen;
                int recordsEnd = fragStart + fragLen;
                pos = recordsEnd;
                if (handshakeHave >= handshakeNeeded)
                {
                    clientHelloRecord = raw.Slice(0, recordsEnd).ToArray();
                    return true;
                }
            }
        }

        /// <summary>
        /// Parses the ALPN protocol list advertised in a captured ClientHello record (as produced by
        /// <see cref="TryExtractClientHello"/>). Returns false when the ClientHello has no ALPN extension.
        /// </summary>
        public static bool TryExtractAlpn(ReadOnlySpan<byte> clientHelloRecord, out List<string> protocols)
        {
            protocols = new List<string>();
            byte[] handshake = ConcatHandshakeMessage(clientHelloRecord);
            var hs = new ReadOnlySpan<byte>(handshake);

            // Handshake header: type(1) + length(3). Body is the ClientHello.
            int p = 4;
            if (p + 2 + 32 > hs.Length) return false;
            p += 2;  // legacy_version
            p += 32; // random
            if (p + 1 > hs.Length) return false;
            int sessionIdLen = hs[p++];
            p += sessionIdLen;
            if (p + 2 > hs.Length) return false;
            int cipherSuitesLen = (hs[p] << 8) | hs[p + 1];
            p += 2 + cipherSuitesLen;
            if (p + 1 > hs.Length) return false;
            int compLen = hs[p++];
            p += compLen;
            if (p + 2 > hs.Length) return false;
            int extensionsLen = (hs[p] << 8) | hs[p + 1];
            p += 2;
            int extEnd = p + extensionsLen;
            if (extEnd > hs.Length) extEnd = hs.Length;

            while (p + 4 <= extEnd)
            {
                int extType = (hs[p] << 8) | hs[p + 1];
                int extLen = (hs[p + 2] << 8) | hs[p + 3];
                int body = p + 4;
                if (body + extLen > extEnd) return false;

                if (extType == AlpnExtensionType)
                {
                    int q = body;
                    if (q + 2 > body + extLen) return false;
                    int listLen = (hs[q] << 8) | hs[q + 1];
                    q += 2;
                    int listEnd = Math.Min(q + listLen, body + extLen);
                    while (q + 1 <= listEnd)
                    {
                        int nameLen = hs[q++];
                        if (q + nameLen > listEnd) break;
                        protocols.Add(System.Text.Encoding.ASCII.GetString(handshake, q, nameLen));
                        q += nameLen;
                    }
                    return protocols.Count > 0;
                }

                p = body + extLen;
            }
            return false;
        }

        /// <summary>Concatenates the handshake-message fragments across one or more TLS records (strips record headers).</summary>
        private static byte[] ConcatHandshakeMessage(ReadOnlySpan<byte> records)
        {
            using var ms = new System.IO.MemoryStream();
            int pos = 0;
            while (pos + 5 <= records.Length)
            {
                if (records[pos] != HandshakeContentType) break;
                int fragLen = (records[pos + 3] << 8) | records[pos + 4];
                int fragStart = pos + 5;
                if (fragStart + fragLen > records.Length) break;
                ms.Write(records.Slice(fragStart, fragLen));
                pos = fragStart + fragLen;
            }
            return ms.ToArray();
        }
    }
}
