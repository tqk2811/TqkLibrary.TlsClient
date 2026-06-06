using System.Runtime.InteropServices;

namespace TqkLibrary.TlsClient.Native
{
    /// <summary>
    /// P/Invoke bindings for the native uTLS codec (tqktls). The transport (TCP/proxy) is owned
    /// by the C# side; the native code reads/writes ciphertext through the supplied callbacks and
    /// exposes plaintext via <see cref="TlsRead"/> / <see cref="TlsWrite"/>.
    /// </summary>
    internal static unsafe class NativeMethods
    {
        private const string Lib = "tqktls";

        /// <summary>
        /// Create a codec connection over a callback-backed transport. Returns a handle (&gt;0) or &lt;=0 on error.
        /// </summary>
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern long TlsNew(
            byte* optsJsonUtf8,
            delegate* unmanaged[Cdecl]<void*, byte*, int, int> readCb,
            delegate* unmanaged[Cdecl]<void*, byte*, int, int> writeCb,
            delegate* unmanaged[Cdecl]<void*, void> closeCb,
            void* ctx);

        /// <summary>Perform the TLS handshake. Returns null on success, or an error C-string (free with <see cref="TlsFreeString"/>).</summary>
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern byte* TlsHandshake(long id);

        /// <summary>Read plaintext. Returns bytes read (&gt;0), 0 on EOF, or -1 on error.</summary>
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int TlsRead(long id, byte* buf, int len);

        /// <summary>Write plaintext. Returns bytes written, or -1 on error.</summary>
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int TlsWrite(long id, byte* buf, int len);

        /// <summary>Negotiated ALPN protocol as a C-string (free with <see cref="TlsFreeString"/>).</summary>
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern byte* TlsGetAlpn(long id);

        /// <summary>Close and release the connection handle.</summary>
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern void TlsClose(long id);

        /// <summary>Free a C-string returned by the native side.</summary>
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern void TlsFreeString(byte* s);
    }
}
