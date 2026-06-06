namespace TqkLibrary.TlsClient.Http2.Models
{
    /// <summary>A PRIORITY frame to emit during connection setup (part of the Akamai h2 fingerprint).</summary>
    public sealed class Http2PriorityFrame
    {
        public Http2PriorityFrame(int streamId, bool exclusive, int streamDependency, byte weight)
        {
            StreamId = streamId;
            Exclusive = exclusive;
            StreamDependency = streamDependency;
            Weight = weight;
        }

        public int StreamId { get; }
        public bool Exclusive { get; }
        public int StreamDependency { get; }

        /// <summary>Wire weight value (0..255). The "weight" field in HTTP/2 is this value + 1.</summary>
        public byte Weight { get; }
    }
}
