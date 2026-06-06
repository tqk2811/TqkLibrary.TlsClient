using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace TqkLibrary.TlsClient.Native
{
    /// <summary>
    /// Bridges the native uTLS codec to a managed transport <see cref="Stream"/> (ciphertext side).
    /// The native code calls the static unmanaged callbacks below to read/write/close the transport;
    /// the per-connection instance is recovered from the <c>ctx</c> pointer (a pinned <see cref="GCHandle"/>).
    /// Reads/writes are blocking by design — the native call is expected to run on an I/O thread.
    /// </summary>
    internal sealed unsafe class TransportBridge : IDisposable
    {
        private readonly Stream _inner;
        private readonly bool _ownsInner;
        private GCHandle _self;

        public TransportBridge(Stream inner, bool ownsInner)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _ownsInner = ownsInner;
            _self = GCHandle.Alloc(this);
        }

        /// <summary>Opaque context handed to the native side and passed back into the callbacks.</summary>
        public void* Context => (void*)GCHandle.ToIntPtr(_self);

        public static delegate* unmanaged[Cdecl]<void*, byte*, int, int> ReadPtr => &ReadCb;
        public static delegate* unmanaged[Cdecl]<void*, byte*, int, int> WritePtr => &WriteCb;
        public static delegate* unmanaged[Cdecl]<void*, void> ClosePtr => &CloseCb;

        private static TransportBridge? FromCtx(void* ctx)
        {
            if (ctx == null) return null;
            var h = GCHandle.FromIntPtr((IntPtr)ctx);
            return h.IsAllocated ? h.Target as TransportBridge : null;
        }

        [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
        private static int ReadCb(void* ctx, byte* buf, int len)
        {
            var self = FromCtx(ctx);
            if (self is null || len < 0) return -1;
            try
            {
                // 0 bytes read => EOF on the underlying transport (the native side treats 0 as EOF).
                return self._inner.Read(new Span<byte>(buf, len));
            }
            catch
            {
                return -1;
            }
        }

        [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
        private static int WriteCb(void* ctx, byte* buf, int len)
        {
            var self = FromCtx(ctx);
            if (self is null || len < 0) return -1;
            try
            {
                self._inner.Write(new ReadOnlySpan<byte>(buf, len));
                return len;
            }
            catch
            {
                return -1;
            }
        }

        [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
        private static void CloseCb(void* ctx)
        {
            var self = FromCtx(ctx);
            if (self is null) return;
            try
            {
                if (self._ownsInner) self._inner.Dispose();
            }
            catch
            {
                // best effort
            }
        }

        public void Dispose()
        {
            if (_self.IsAllocated) _self.Free();
        }
    }
}
