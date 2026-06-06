using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace TqkLibrary.TlsClient.Native.Helpers
{
    /// <summary>Verifies a server certificate's SAN (or CN fallback) against the requested host (RFC 6125).</summary>
    internal static class HostnameVerifier
    {
        private const string SubjectAltNameOid = "2.5.29.17";

        public static bool Matches(X509Certificate2 certificate, string host)
        {
            if (string.IsNullOrEmpty(host)) return false;

            List<string> dnsNames = GetSanDnsNames(certificate);
            if (dnsNames.Count == 0)
            {
                string cn = certificate.GetNameInfo(X509NameType.SimpleName, false);
                if (!string.IsNullOrEmpty(cn)) dnsNames.Add(cn);
            }

            foreach (string pattern in dnsNames)
                if (MatchesPattern(host, pattern))
                    return true;
            return false;
        }

        private static List<string> GetSanDnsNames(X509Certificate2 certificate)
        {
            var names = new List<string>();
            foreach (X509Extension ext in certificate.Extensions)
            {
                if (ext.Oid?.Value != SubjectAltNameOid) continue;
                try
                {
                    var reader = new AsnReader(ext.RawData, AsnEncodingRules.DER);
                    AsnReader seq = reader.ReadSequence();
                    var dnsTag = new Asn1Tag(TagClass.ContextSpecific, 2); // dNSName [2] IMPLICIT IA5String
                    while (seq.HasData)
                    {
                        Asn1Tag tag = seq.PeekTag();
                        if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 2)
                            names.Add(seq.ReadCharacterString(UniversalTagNumber.IA5String, dnsTag));
                        else
                            seq.ReadEncodedValue();
                    }
                }
                catch (AsnContentException)
                {
                    // ignore a malformed SAN extension
                }
            }
            return names;
        }

        private static bool MatchesPattern(string host, string pattern)
        {
            host = host.TrimEnd('.');
            pattern = pattern.TrimEnd('.');
            if (pattern.Length == 0) return false;

            if (pattern.StartsWith("*.", StringComparison.Ordinal))
            {
                // A wildcard matches exactly one left-most label.
                int dot = host.IndexOf('.');
                if (dot <= 0) return false;
                return string.Equals(host.Substring(dot + 1), pattern.Substring(2), StringComparison.OrdinalIgnoreCase);
            }
            return string.Equals(host, pattern, StringComparison.OrdinalIgnoreCase);
        }
    }
}
