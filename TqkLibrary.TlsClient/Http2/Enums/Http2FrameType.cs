namespace TqkLibrary.TlsClient.Http2.Enums
{
    /// <summary>HTTP/2 frame types (RFC 7540 §6).</summary>
    public enum Http2FrameType : byte
    {
        Data = 0x0,
        Headers = 0x1,
        Priority = 0x2,
        RstStream = 0x3,
        Settings = 0x4,
        PushPromise = 0x5,
        Ping = 0x6,
        GoAway = 0x7,
        WindowUpdate = 0x8,
        Continuation = 0x9,
    }
}
