using System.Collections.Generic;
using TqkLibrary.TlsClient.Http2.Enums;

namespace TqkLibrary.TlsClient.Http2.Models
{
    /// <summary>
    /// Data-driven HTTP/2 fingerprint: the SETTINGS (and their order), the initial connection
    /// WINDOW_UPDATE, any PRIORITY frames, and the pseudo-header order. Together these determine the
    /// Akamai h2 fingerprint. Capture these from a real browser (via a proxy) and store them here.
    /// </summary>
    public sealed class Http2FingerprintConfig
    {
        /// <summary>SETTINGS to send, in order.</summary>
        public IReadOnlyList<Http2Setting> Settings { get; set; } = new List<Http2Setting>();

        /// <summary>Initial connection-level WINDOW_UPDATE increment (0 = don't send).</summary>
        public uint ConnectionWindowUpdateIncrement { get; set; }

        /// <summary>Standalone PRIORITY frames to send during setup (empty for modern Chrome).</summary>
        public IReadOnlyList<Http2PriorityFrame> Priorities { get; set; } = new List<Http2PriorityFrame>();

        /// <summary>Pseudo-header order, e.g. [":method", ":authority", ":scheme", ":path"] (Akamai "m,a,s,p").</summary>
        public IReadOnlyList<string> PseudoHeaderOrder { get; set; } = new[] { ":method", ":authority", ":scheme", ":path" };

        /// <summary>The INITIAL_WINDOW_SIZE we advertise (from <see cref="Settings"/>), used for receive flow control.</summary>
        public uint InitialWindowSize
        {
            get
            {
                foreach (var s in Settings)
                    if (s.Id == (ushort)Http2SettingId.InitialWindowSize)
                        return s.Value;
                return 65535;
            }
        }

        /// <summary>A recent-Chrome HTTP/2 fingerprint. Akamai: 1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p.</summary>
        public static Http2FingerprintConfig Chrome() => new()
        {
            Settings = new List<Http2Setting>
            {
                new(Http2SettingId.HeaderTableSize, 65536),
                new(Http2SettingId.EnablePush, 0),
                new(Http2SettingId.InitialWindowSize, 6291456),
                new(Http2SettingId.MaxHeaderListSize, 262144),
            },
            ConnectionWindowUpdateIncrement = 15663105,
            Priorities = new List<Http2PriorityFrame>(),
            PseudoHeaderOrder = new[] { ":method", ":authority", ":scheme", ":path" },
        };
    }
}
