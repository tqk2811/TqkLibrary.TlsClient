using System;
using System.Collections.Concurrent;

namespace TqkLibrary.TlsClient.Pooling
{
    /// <summary>
    /// A simple idle-connection pool keyed by host:port. Connections are reused for sequential requests;
    /// a stale (server-closed) connection is detected when the next request fails and is discarded.
    /// </summary>
    internal sealed class TlsConnectionPool : IDisposable
    {
        private readonly ConcurrentDictionary<string, ConcurrentBag<PooledConnection>> _idle = new();
        private readonly int _maxIdlePerKey;

        public TlsConnectionPool(int maxIdlePerKey = 8) => _maxIdlePerKey = maxIdlePerKey;

        public PooledConnection? Rent(string key)
            => _idle.TryGetValue(key, out var bag) && bag.TryTake(out var conn) ? conn : null;

        public void Return(string key, PooledConnection conn)
        {
            ConcurrentBag<PooledConnection> bag = _idle.GetOrAdd(key, static _ => new ConcurrentBag<PooledConnection>());
            if (bag.Count >= _maxIdlePerKey)
            {
                conn.Dispose();
                return;
            }
            bag.Add(conn);
        }

        public void Dispose()
        {
            foreach (ConcurrentBag<PooledConnection> bag in _idle.Values)
                while (bag.TryTake(out PooledConnection? conn))
                    conn.Dispose();
            _idle.Clear();
        }
    }
}
