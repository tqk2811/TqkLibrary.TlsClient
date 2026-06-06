using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace TqkLibrary.TlsClient.Http2.Hpack
{
    /// <summary>
    /// Stateful HPACK decoder (RFC 7541): integer/string primitives, the static table, a dynamic table
    /// with eviction, and Huffman decoding. One instance per connection (the dynamic table is connection state).
    /// </summary>
    internal sealed class HpackDecoder
    {
        private readonly List<(string Name, string Value)> _dynamicTable = new();
        private int _dynamicSize;
        private int _maxDynamicSize;

        public HpackDecoder(int maxDynamicSize = 65536) => _maxDynamicSize = maxDynamicSize;

        public List<KeyValuePair<string, string>> Decode(ReadOnlySpan<byte> block)
        {
            var headers = new List<KeyValuePair<string, string>>();
            int pos = 0;
            while (pos < block.Length)
            {
                byte b = block[pos];
                if ((b & 0x80) != 0)
                {
                    // Indexed header field.
                    int index = DecodeInteger(block, ref pos, 7);
                    var (name, value) = GetIndexed(index);
                    headers.Add(new KeyValuePair<string, string>(name, value));
                }
                else if ((b & 0x40) != 0)
                {
                    // Literal with incremental indexing.
                    int index = DecodeInteger(block, ref pos, 6);
                    string name = index == 0 ? DecodeString(block, ref pos) : GetIndexed(index).Name;
                    string value = DecodeString(block, ref pos);
                    AddDynamic(name, value);
                    headers.Add(new KeyValuePair<string, string>(name, value));
                }
                else if ((b & 0x20) != 0)
                {
                    // Dynamic table size update.
                    int newSize = DecodeInteger(block, ref pos, 5);
                    SetMaxDynamicSize(newSize);
                }
                else
                {
                    // Literal without indexing (0x00) or never indexed (0x10).
                    int index = DecodeInteger(block, ref pos, 4);
                    string name = index == 0 ? DecodeString(block, ref pos) : GetIndexed(index).Name;
                    string value = DecodeString(block, ref pos);
                    headers.Add(new KeyValuePair<string, string>(name, value));
                }
            }
            return headers;
        }

        private static int DecodeInteger(ReadOnlySpan<byte> block, ref int pos, int prefixBits)
        {
            int max = (1 << prefixBits) - 1;
            int value = block[pos++] & max;
            if (value < max) return value;

            int shift = 0;
            byte b;
            do
            {
                b = block[pos++];
                value += (b & 0x7f) << shift;
                shift += 7;
            }
            while ((b & 0x80) != 0);
            return value;
        }

        private static string DecodeString(ReadOnlySpan<byte> block, ref int pos)
        {
            bool huffman = (block[pos] & 0x80) != 0;
            int length = DecodeInteger(block, ref pos, 7);
            ReadOnlySpan<byte> bytes = block.Slice(pos, length);
            pos += length;
            return huffman
                ? Encoding.Latin1.GetString(HpackHuffman.Decode(bytes))
                : Encoding.Latin1.GetString(bytes);
        }

        private (string Name, string Value) GetIndexed(int index)
        {
            if (index >= 1 && index <= HpackStaticTable.Entries.Length)
                return HpackStaticTable.Entries[index - 1];

            int dynamicIndex = index - HpackStaticTable.Entries.Length - 1;
            if (dynamicIndex >= 0 && dynamicIndex < _dynamicTable.Count)
                return _dynamicTable[dynamicIndex];

            throw new IOException($"Invalid HPACK table index {index}.");
        }

        private void AddDynamic(string name, string value)
        {
            _dynamicTable.Insert(0, (name, value));
            _dynamicSize += EntrySize(name, value);
            Evict();
        }

        private void SetMaxDynamicSize(int newSize)
        {
            _maxDynamicSize = newSize;
            Evict();
        }

        private void Evict()
        {
            while (_dynamicSize > _maxDynamicSize && _dynamicTable.Count > 0)
            {
                var (name, value) = _dynamicTable[_dynamicTable.Count - 1];
                _dynamicTable.RemoveAt(_dynamicTable.Count - 1);
                _dynamicSize -= EntrySize(name, value);
            }
        }

        // RFC 7541 §4.1: entry size = name octets + value octets + 32.
        private static int EntrySize(string name, string value) => name.Length + value.Length + 32;
    }
}
