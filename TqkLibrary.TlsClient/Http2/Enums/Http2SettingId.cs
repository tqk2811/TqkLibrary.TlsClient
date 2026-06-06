namespace TqkLibrary.TlsClient.Http2.Enums
{
    /// <summary>HTTP/2 SETTINGS parameter identifiers (RFC 7540 §6.5.2).</summary>
    public enum Http2SettingId : ushort
    {
        HeaderTableSize = 0x1,
        EnablePush = 0x2,
        MaxConcurrentStreams = 0x3,
        InitialWindowSize = 0x4,
        MaxFrameSize = 0x5,
        MaxHeaderListSize = 0x6,
    }
}
