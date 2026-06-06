using System;
using System.Collections.Generic;
using TqkLibrary.TlsClient.Http2.Hpack;
using Xunit;

namespace TqkLibrary.TlsClient.Tests
{
    public class HpackDecoderTests
    {
        private static List<KeyValuePair<string, string>> Decode(HpackDecoder d, string hex)
            => d.Decode(Convert.FromHexString(hex));

        private static void AssertHeaders(List<KeyValuePair<string, string>> actual, params (string Name, string Value)[] expected)
        {
            Assert.Equal(expected.Length, actual.Count);
            for (int i = 0; i < expected.Length; i++)
            {
                Assert.Equal(expected[i].Name, actual[i].Key);
                Assert.Equal(expected[i].Value, actual[i].Value);
            }
        }

        [Fact] // RFC 7541 C.3.1 — request, no Huffman.
        public void Request_NoHuffman()
        {
            var headers = Decode(new HpackDecoder(), "828684410f7777772e6578616d706c652e636f6d");
            AssertHeaders(headers,
                (":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com"));
        }

        [Fact] // RFC 7541 C.4.1 — request, Huffman-encoded :authority.
        public void Request_Huffman()
        {
            var headers = Decode(new HpackDecoder(), "828684418cf1e3c2e5f23a6ba0ab90f4ff");
            AssertHeaders(headers,
                (":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com"));
        }

        [Fact] // RFC 7541 C.6.1 — response, Huffman-encoded values (status, cache-control, date, location).
        public void Response_Huffman()
        {
            var headers = Decode(new HpackDecoder(),
                "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3");
            AssertHeaders(headers,
                (":status", "302"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"));
        }

        [Fact] // The minimal encoder must round-trip through the decoder.
        public void Encoder_RoundTripsThroughDecoder()
        {
            var input = new[]
            {
                new KeyValuePair<string, string>(":method", "GET"),
                new KeyValuePair<string, string>(":authority", "example.com:8443"),
                new KeyValuePair<string, string>(":path", "/a/b?c=1&d=2"),
                new KeyValuePair<string, string>("user-agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/124.0.0.0"),
                new KeyValuePair<string, string>("accept", "*/*"),
            };
            byte[] block = HpackEncoder.Encode(input);
            var decoded = new HpackDecoder().Decode(block);

            Assert.Equal(input.Length, decoded.Count);
            for (int i = 0; i < input.Length; i++)
            {
                Assert.Equal(input[i].Key, decoded[i].Key);
                Assert.Equal(input[i].Value, decoded[i].Value);
            }
        }

        [Fact] // Dynamic table reuse across header blocks on the same decoder (RFC 7541 C.3.1 -> C.3.2).
        public void DynamicTable_ReusedAcrossBlocks()
        {
            var decoder = new HpackDecoder();
            Decode(decoder, "828684410f7777772e6578616d706c652e636f6d"); // adds :authority=www.example.com to dynamic table
            var second = Decode(decoder, "828684be58086e6f2d6361636865");
            AssertHeaders(second,
                (":method", "GET"), (":scheme", "http"), (":path", "/"),
                (":authority", "www.example.com"), // index 0xbe references the dynamic entry
                ("cache-control", "no-cache"));
        }
    }
}
