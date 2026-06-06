using System;
using System.Collections.Generic;

namespace TqkLibrary.TlsClient.Http2.Hpack
{
    /// <summary>HPACK Huffman encoder (RFC 7541 §5.2), using <see cref="HpackHuffmanTable"/>. Pads with EOS 1-bits.</summary>
    internal static class HpackHuffmanEncoder
    {
        public static byte[] Encode(ReadOnlySpan<byte> input)
        {
            var entries = HpackHuffmanTable.Entries;
            var output = new List<byte>(input.Length);
            ulong buffer = 0;
            int bits = 0;

            foreach (byte b in input)
            {
                uint code = entries[b].Code;
                int len = entries[b].Bits;
                buffer = (buffer << len) | code;
                bits += len;
                while (bits >= 8)
                {
                    bits -= 8;
                    output.Add((byte)(buffer >> bits));
                }
                buffer &= bits == 0 ? 0UL : (1UL << bits) - 1;
            }

            if (bits > 0)
            {
                int pad = 8 - bits;
                output.Add((byte)((buffer << pad) | ((1UL << pad) - 1))); // pad with EOS (all-1) bits
            }
            return output.ToArray();
        }

        /// <summary>Encoded length in bytes, without producing the output (used to pick Huffman vs literal).</summary>
        public static int EncodedLength(ReadOnlySpan<byte> input)
        {
            var entries = HpackHuffmanTable.Entries;
            long bits = 0;
            foreach (byte b in input) bits += entries[b].Bits;
            return (int)((bits + 7) / 8);
        }
    }
}
