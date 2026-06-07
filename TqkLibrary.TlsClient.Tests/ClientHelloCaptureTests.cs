using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using TqkLibrary.TlsClient.Capture;
using TqkLibrary.TlsClient.Profiles;
using Xunit;

namespace TqkLibrary.TlsClient.Tests
{
    public class ClientHelloCaptureTests
    {
        // Builds a minimal but well-formed TLS ClientHello record carrying the given ALPN protocols.
        private static byte[] BuildClientHelloRecord(params string[] alpn)
        {
            var body = new List<byte>();
            body.AddRange(new byte[] { 0x03, 0x03 });          // legacy_version TLS 1.2
            body.AddRange(new byte[32]);                        // random
            body.Add(0x00);                                    // session_id length 0
            body.AddRange(new byte[] { 0x00, 0x02, 0x13, 0x01 }); // cipher_suites: len 2, TLS_AES_128_GCM_SHA256
            body.AddRange(new byte[] { 0x01, 0x00 });          // compression_methods: len 1, null

            // ALPN extension (type 0x0010): ProtocolNameList of (len-prefixed) protocol strings.
            var nameList = new List<byte>();
            foreach (string p in alpn)
            {
                byte[] bytes = Encoding.ASCII.GetBytes(p);
                nameList.Add((byte)bytes.Length);
                nameList.AddRange(bytes);
            }
            var alpnExt = new List<byte> { 0x00, 0x10 };       // extension type
            int extBodyLen = 2 + nameList.Count;               // list length field + entries
            alpnExt.Add((byte)(extBodyLen >> 8)); alpnExt.Add((byte)extBodyLen);
            alpnExt.Add((byte)(nameList.Count >> 8)); alpnExt.Add((byte)nameList.Count);
            alpnExt.AddRange(nameList);

            int extensionsLen = alpnExt.Count;
            body.Add((byte)(extensionsLen >> 8)); body.Add((byte)extensionsLen);
            body.AddRange(alpnExt);

            var handshake = new List<byte> { 0x01 };           // client_hello
            handshake.Add((byte)(body.Count >> 16)); handshake.Add((byte)(body.Count >> 8)); handshake.Add((byte)body.Count);
            handshake.AddRange(body);

            var record = new List<byte> { 0x16, 0x03, 0x01 };  // handshake record, TLS 1.0 record version
            record.Add((byte)(handshake.Count >> 8)); record.Add((byte)handshake.Count);
            record.AddRange(handshake);
            return record.ToArray();
        }

        [Fact]
        public void ExtractsClientHelloRecord_ExcludingTrailingBytes()
        {
            byte[] record = BuildClientHelloRecord("h2", "http/1.1");
            byte[] raw = record.Concat(new byte[] { 0xAA, 0xBB, 0xCC }).ToArray(); // trailing non-handshake bytes

            Assert.True(ClientHelloCapture.TryExtractClientHello(raw, out byte[] got));
            Assert.Equal(record, got); // verbatim record, trailing bytes excluded
        }

        [Fact]
        public void ExtractsAlpn_FromClientHello()
        {
            byte[] record = BuildClientHelloRecord("h2", "http/1.1");
            Assert.True(ClientHelloCapture.TryExtractAlpn(record, out List<string> alpn));
            Assert.Equal(new[] { "h2", "http/1.1" }, alpn);
        }

        [Fact]
        public void NonHandshakeBytes_AreNotAClientHello()
        {
            Assert.False(ClientHelloCapture.TryExtractClientHello(new byte[] { 0x17, 0x03, 0x03, 0x00, 0x01, 0x00 }, out _));
        }

        [Fact]
        public void FromCapturedHandshake_BuildsProfileWithRecordAndAlpn()
        {
            byte[] record = BuildClientHelloRecord("h2", "http/1.1");
            byte[] raw = record.Concat(new byte[] { 0x00, 0x00 }).ToArray();

            TlsProfile profile = TlsProfile.FromCapturedHandshake(raw);

            Assert.Equal(Convert.ToBase64String(record), profile.RawClientHelloBase64);
            Assert.Equal(new[] { "h2", "http/1.1" }, profile.Alpn.ToArray());
        }

        [Fact]
        public void CaptureStream_SniffsClientHelloWhileRelaying()
        {
            byte[] record = BuildClientHelloRecord("h2");
            using var inner = new MemoryStream(record);
            using var tee = new ClientHelloCaptureStream(inner);

            using var relayed = new MemoryStream();
            var buffer = new byte[5]; // small chunks to exercise incremental sniffing
            int n;
            while ((n = tee.Read(buffer, 0, buffer.Length)) > 0)
                relayed.Write(buffer, 0, n);

            Assert.True(tee.Captured);
            Assert.Equal(record, tee.CapturedClientHello);
            Assert.Equal(record, relayed.ToArray()); // bytes passed through unchanged
        }
    }
}
