using System;
using System.Collections.Generic;
using System.IO;

namespace TqkLibrary.TlsClient.Http2.Hpack
{
    /// <summary>HPACK Huffman decoder (RFC 7541 §5.2), built as a bit-walk tree from <see cref="HpackHuffmanTable"/>.</summary>
    internal static class HpackHuffman
    {
        private sealed class Node
        {
            public Node? Zero;
            public Node? One;
            public int Symbol = -1;
        }

        private static readonly Node Root = BuildTree();

        private static Node BuildTree()
        {
            var root = new Node();
            var entries = HpackHuffmanTable.Entries;
            for (int symbol = 0; symbol < 256; symbol++) // 256 = EOS, not a decodable leaf
            {
                uint code = entries[symbol].Code;
                int bits = entries[symbol].Bits;
                Node node = root;
                for (int i = bits - 1; i >= 0; i--)
                {
                    int bit = (int)((code >> i) & 1);
                    node = bit == 0 ? (node.Zero ??= new Node()) : (node.One ??= new Node());
                }
                node.Symbol = symbol;
            }
            return root;
        }

        public static byte[] Decode(ReadOnlySpan<byte> input)
        {
            var output = new List<byte>(input.Length * 8 / 5 + 1);
            Node node = Root;
            int sinceSymbol = 0;
            bool allOnes = true;

            foreach (byte octet in input)
            {
                for (int i = 7; i >= 0; i--)
                {
                    int bit = (octet >> i) & 1;
                    node = bit == 0 ? node.Zero! : node.One!;
                    if (node is null) throw new IOException("Invalid HPACK Huffman code.");
                    sinceSymbol++;
                    if (bit == 0) allOnes = false;
                    if (node.Symbol >= 0)
                    {
                        output.Add((byte)node.Symbol);
                        node = Root;
                        sinceSymbol = 0;
                        allOnes = true;
                    }
                }
            }

            // Any leftover bits must be the EOS prefix: all 1s and shorter than a full octet.
            if (node != Root && (sinceSymbol >= 8 || !allOnes))
                throw new IOException("Invalid HPACK Huffman padding.");

            return output.ToArray();
        }
    }
}
