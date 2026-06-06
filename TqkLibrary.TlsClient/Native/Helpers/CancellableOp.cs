using System;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.TlsClient.Native.Helpers
{
    /// <summary>
    /// Runs a blocking native operation on a thread-pool thread. Because the native call can't be
    /// interrupted directly, cancellation invokes the supplied abort action (which aborts the transport,
    /// making the blocked call fault and unwind), and the result surfaces as an OperationCanceledException.
    /// </summary>
    internal static class CancellableOp
    {
        public static async Task<T> RunAsync<T>(Func<T> work, Action onCancel, CancellationToken ct)
        {
            if (!ct.CanBeCanceled)
                return await Task.Run(work).ConfigureAwait(false);

            using CancellationTokenRegistration reg = ct.Register(onCancel);
            try
            {
                T result = await Task.Run(work, ct).ConfigureAwait(false);
                // The abort may have made the blocked call return a benign value (e.g. 0/EOF) rather than throw.
                ct.ThrowIfCancellationRequested();
                return result;
            }
            catch when (ct.IsCancellationRequested)
            {
                throw new OperationCanceledException(ct);
            }
        }
    }
}
