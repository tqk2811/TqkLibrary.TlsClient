using System;

namespace TqkLibrary.TlsClient.Http2.Enums
{
    /// <summary>HTTP/2 frame flags. Note some values are context-specific (Ack vs EndStream share 0x1).</summary>
    [Flags]
    public enum Http2FrameFlags : byte
    {
        None = 0x0,
        EndStream = 0x1,
        Ack = 0x1,
        EndHeaders = 0x4,
        Padded = 0x8,
        Priority = 0x20,
    }
}
