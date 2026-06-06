using System.Collections.Generic;
using System.IO;
using System.Text;

namespace TqkLibrary.TlsClient.Http2.Hpack
{
    /// <summary>
    /// Minimal HPACK encoder: emits each header as a literal field "without indexing, new name"
    /// (no Huffman, no dynamic table). This is valid HPACK and keeps the encoder stateless. The
    /// Akamai h2 fingerprint does not depend on HPACK byte encoding, so this is sufficient for now.
    /// (Chrome-exact HPACK byte output can be added later if a tool fingerprints it.)
    /// </summary>
    internal static class HpackEncoder
    {
        public static byte[] Encode(IEnumerable<KeyValuePair<string, string>> headers)
        {
            using var ms = new MemoryStream();
            foreach (var header in headers)
            {
                ms.WriteByte(0x00); // literal header field without indexing — new name
                WriteString(ms, header.Key);
                WriteString(ms, header.Value);
            }
            return ms.ToArray();
        }

        private static void WriteString(Stream s, string value)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value);
            WriteInteger(s, bytes.Length, prefixBits: 7, firstByte: 0x00); // H=0, no Huffman
            s.Write(bytes, 0, bytes.Length);
        }

        // HPACK integer encoding (RFC 7541 §5.1). prefixBits in [1..8]; firstByte holds the flag bits above the prefix.
        private static void WriteInteger(Stream s, int value, int prefixBits, byte firstByte)
        {
            int max = (1 << prefixBits) - 1;
            if (value < max)
            {
                s.WriteByte((byte)(firstByte | value));
                return;
            }
            s.WriteByte((byte)(firstByte | max));
            value -= max;
            while (value >= 0x80)
            {
                s.WriteByte((byte)((value & 0x7f) | 0x80));
                value >>= 7;
            }
            s.WriteByte((byte)value);
        }
    }
}
