using System;
using System.Collections.Generic;
using System.Text;
using TqkLibrary.TlsClient.Http2.Hpack;
using Xunit;

namespace TqkLibrary.TlsClient.Tests
{
    public class HpackEncoderTests
    {
        [Fact] // RFC 7541 C.4.1 Huffman("www.example.com").
        public void Huffman_Encodes_RfcVector()
        {
            byte[] encoded = HpackHuffmanEncoder.Encode(Encoding.ASCII.GetBytes("www.example.com"));
            Assert.Equal("f1e3c2e5f23a6ba0ab90f4ff", Convert.ToHexString(encoded).ToLowerInvariant());
        }

        [Fact] // An exact static-table match is a single indexed byte (":method GET" == index 2).
        public void Encoder_UsesStaticIndex_ForExactMatch()
        {
            byte[] block = HpackEncoder.Encode(new[] { new KeyValuePair<string, string>(":method", "GET") });
            Assert.Equal(new byte[] { 0x82 }, block);
        }

        [Fact] // A header with a static name but a custom value uses an indexed name + (Huffman) literal value.
        public void Encoder_UsesIndexedName_ForNameMatch()
        {
            byte[] block = HpackEncoder.Encode(new[] { new KeyValuePair<string, string>(":authority", "example.com") });
            var decoded = new HpackDecoder().Decode(block);
            Assert.Single(decoded);
            Assert.Equal(":authority", decoded[0].Key);
            Assert.Equal("example.com", decoded[0].Value);
            Assert.Equal(0x41, block[0]); // literal incremental indexing, name index 1 (:authority)
        }
    }
}
