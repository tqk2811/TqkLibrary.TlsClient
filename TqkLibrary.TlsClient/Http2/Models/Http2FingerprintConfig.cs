using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
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
        [JsonIgnore]
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

        /// <summary>
        /// Render the Akamai h2 fingerprint string: "SETTINGS|WINDOW_UPDATE|PRIORITY|HEADER_ORDER", e.g.
        /// "1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p".
        /// </summary>
        public string ToAkamai()
        {
            string settings = string.Join(",", Settings.Select(s => $"{s.Id}:{s.Value}"));
            string window = ConnectionWindowUpdateIncrement.ToString();
            string priority = Priorities.Count == 0
                ? "0"
                : string.Join(",", Priorities.Select(p => $"{p.StreamId}:{(p.Exclusive ? 1 : 0)}:{p.StreamDependency}:{p.Weight + 1}"));
            string order = string.Join(",", PseudoHeaderOrder.Select(PseudoToLetter));
            return $"{settings}|{window}|{priority}|{order}";
        }

        /// <summary>
        /// Parse an Akamai h2 fingerprint string (as reported by tools/proxies) into a config. The PRIORITY
        /// weight is the HTTP/2 weight (wire value + 1), matching how tools report it.
        /// </summary>
        public static Http2FingerprintConfig FromAkamai(string akamai)
        {
            if (akamai is null) throw new ArgumentNullException(nameof(akamai));
            string[] parts = akamai.Split('|');
            if (parts.Length != 4) throw new FormatException("Akamai fingerprint must have 4 '|'-separated fields.");

            var settings = new List<Http2Setting>();
            if (parts[0].Length > 0)
                foreach (string token in parts[0].Split(','))
                {
                    string[] kv = token.Split(':');
                    settings.Add(new Http2Setting(ushort.Parse(kv[0]), uint.Parse(kv[1])));
                }

            uint window = parts[1] is "0" or "00" or "" ? 0u : uint.Parse(parts[1]);

            var priorities = new List<Http2PriorityFrame>();
            if (parts[2] is not ("0" or ""))
                foreach (string token in parts[2].Split(','))
                {
                    string[] f = token.Split(':');
                    priorities.Add(new Http2PriorityFrame(int.Parse(f[0]), f[1] == "1", int.Parse(f[2]), (byte)(byte.Parse(f[3]) - 1)));
                }

            string[] order = parts[3].Split(',').Select(LetterToPseudo).ToArray();

            return new Http2FingerprintConfig
            {
                Settings = settings,
                ConnectionWindowUpdateIncrement = window,
                Priorities = priorities,
                PseudoHeaderOrder = order,
            };
        }

        private static string PseudoToLetter(string pseudo) => pseudo switch
        {
            ":method" => "m",
            ":authority" => "a",
            ":scheme" => "s",
            ":path" => "p",
            _ => pseudo,
        };

        private static string LetterToPseudo(string letter) => letter switch
        {
            "m" => ":method",
            "a" => ":authority",
            "s" => ":scheme",
            "p" => ":path",
            _ => letter,
        };
    }
}
