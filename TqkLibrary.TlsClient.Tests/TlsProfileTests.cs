using System;
using System.Collections.Generic;
using TqkLibrary.TlsClient.Profiles;
using Xunit;

namespace TqkLibrary.TlsClient.Tests
{
    public class TlsProfileTests
    {
        [Fact]
        public void FromCapturedClientHello_EncodesBase64()
        {
            byte[] raw = { 0x16, 0x03, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03 };
            var profile = TlsProfile.FromCapturedClientHello(raw);
            Assert.Equal(Convert.ToBase64String(raw), profile.RawClientHelloBase64);
            Assert.Null(profile.Name);
        }

        [Fact]
        public void Json_RoundTrip_PreservesTlsAndHttp2Fingerprint()
        {
            var profile = TlsProfile.Chrome();
            profile.RawClientHelloBase64 = "AAEC";
            profile.Alpn = new List<string> { "h2" };

            var back = TlsProfile.FromJson(profile.ToJson());

            Assert.Equal(profile.Name, back.Name);
            Assert.Equal(profile.RawClientHelloBase64, back.RawClientHelloBase64);
            Assert.Equal(profile.Alpn, back.Alpn);
            Assert.Equal(profile.Http2.ConnectionWindowUpdateIncrement, back.Http2.ConnectionWindowUpdateIncrement);
            Assert.Equal(profile.Http2.PseudoHeaderOrder, back.Http2.PseudoHeaderOrder);

            Assert.Equal(profile.Http2.Settings.Count, back.Http2.Settings.Count);
            for (int i = 0; i < profile.Http2.Settings.Count; i++)
            {
                Assert.Equal(profile.Http2.Settings[i].Id, back.Http2.Settings[i].Id);
                Assert.Equal(profile.Http2.Settings[i].Value, back.Http2.Settings[i].Value);
            }
        }
    }
}
