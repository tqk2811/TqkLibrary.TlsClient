using TqkLibrary.TlsClient.Http2.Models;
using Xunit;

namespace TqkLibrary.TlsClient.Tests
{
    public class Http2FingerprintConfigTests
    {
        [Fact]
        public void Chrome_ToAkamai_MatchesKnownString()
        {
            Assert.Equal("1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p", Http2FingerprintConfig.Chrome().ToAkamai());
        }

        [Fact]
        public void Akamai_RoundTrips()
        {
            const string akamai = "1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p";
            Assert.Equal(akamai, Http2FingerprintConfig.FromAkamai(akamai).ToAkamai());
        }

        [Fact]
        public void Akamai_ParsesSettingsWindowAndPseudoOrder()
        {
            var cfg = Http2FingerprintConfig.FromAkamai("1:65536,4:6291456|15663105|0|m,a,s,p");
            Assert.Equal(2, cfg.Settings.Count);
            Assert.Equal((ushort)1, cfg.Settings[0].Id);
            Assert.Equal(65536u, cfg.Settings[0].Value);
            Assert.Equal(15663105u, cfg.ConnectionWindowUpdateIncrement);
            Assert.Equal(new[] { ":method", ":authority", ":scheme", ":path" }, cfg.PseudoHeaderOrder);
        }

        [Fact]
        public void Akamai_ParsesPriorities_WithWeightOffset()
        {
            var cfg = Http2FingerprintConfig.FromAkamai("1:65536|0|3:0:0:201,5:0:0:101|m,a,s,p");
            Assert.Equal(2, cfg.Priorities.Count);
            Assert.Equal(3, cfg.Priorities[0].StreamId);
            Assert.Equal((byte)200, cfg.Priorities[0].Weight); // akamai weight 201 -> wire 200
            Assert.Equal("1:65536|0|3:0:0:201,5:0:0:101|m,a,s,p", cfg.ToAkamai());
        }
    }
}
