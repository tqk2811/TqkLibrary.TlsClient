using TqkLibrary.TlsClient.Http2.Enums;

namespace TqkLibrary.TlsClient.Http2.Models
{
    /// <summary>One HTTP/2 SETTINGS parameter. Order is preserved on the wire (part of the h2 fingerprint).</summary>
    public readonly struct Http2Setting
    {
        public Http2Setting(Http2SettingId id, uint value)
        {
            Id = (ushort)id;
            Value = value;
        }

        public Http2Setting(ushort id, uint value)
        {
            Id = id;
            Value = value;
        }

        public ushort Id { get; }
        public uint Value { get; }
    }
}
