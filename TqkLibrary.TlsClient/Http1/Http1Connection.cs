using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.TlsClient.Http1
{
    /// <summary>
    /// Minimal HTTP/1.1 exchange over a (plaintext) stream: writes the request with caller-controlled
    /// header order, then parses the response status line/headers and exposes the body via
    /// <see cref="Http1ContentStream"/>. The connection is reusable (keep-alive): after the body is fully
    /// drained, <see cref="OnResponseDrained"/> fires so a pool can take it back for the next request.
    /// </summary>
    internal sealed class Http1Connection
    {
        private readonly Stream _stream;
        private readonly IDisposable _owner;
        private byte[] _buf = new byte[8192];
        private int _pos;
        private int _len;
        private byte[]? _seed; // bytes over-read past the previous response (start of this one), consumed first

        /// <param name="stream">Plaintext stream (e.g. an authenticated <c>ImpersonatedTlsStream</c>).</param>
        /// <param name="owner">Disposed when the response body is disposed (the TLS connection + transport).</param>
        public Http1Connection(Stream stream, IDisposable owner)
        {
            _stream = stream;
            _owner = owner;
        }

        /// <summary>
        /// Invoked when the response body is disposed, with whether the connection is reusable (keep-alive AND
        /// the body was fully drained). When null, the connection's owner is disposed instead.
        /// </summary>
        public Action<bool>? OnResponseDrained { get; set; }

        public async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            _pos = 0;
            _len = 0; // reset the read buffer for a reused (keep-alive) connection
            await WriteRequestAsync(request, ct).ConfigureAwait(false);
            return await ReadResponseAsync(request, ct).ConfigureAwait(false);
        }

        private async Task WriteRequestAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Uri uri = request.RequestUri!;
            var sb = new StringBuilder(256);
            sb.Append(request.Method.Method).Append(' ').Append(uri.PathAndQuery).Append(" HTTP/1.1\r\n");

            // Host first, like browsers do on HTTP/1.1.
            sb.Append("Host: ").Append(HostHeaderValue(uri, request)).Append("\r\n");

            byte[]? body = null;
            if (request.Content != null)
                body = await request.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);

            // NonValidated preserves the caller's header order and the raw single value (no structured
            // re-parsing/splitting of User-Agent, Accept-Language, ...). The caller controls h1 header order.
            foreach (var header in request.Headers.NonValidated)
            {
                if (IsHost(header.Key)) continue;
                foreach (var value in header.Value)
                    sb.Append(header.Key).Append(": ").Append(value).Append("\r\n");
            }

            if (request.Content != null)
            {
                foreach (var header in request.Content.Headers.NonValidated)
                {
                    if (string.Equals(header.Key, "Content-Length", StringComparison.OrdinalIgnoreCase)) continue;
                    foreach (var value in header.Value)
                        sb.Append(header.Key).Append(": ").Append(value).Append("\r\n");
                }
                sb.Append("Content-Length: ").Append(body!.Length).Append("\r\n");
            }

            sb.Append("\r\n"); // no forced "Connection: close" (keeps the header set browser-like)

            byte[] head = Encoding.ASCII.GetBytes(sb.ToString());
            await _stream.WriteAsync(head, 0, head.Length, ct).ConfigureAwait(false);
            if (body is { Length: > 0 })
                await _stream.WriteAsync(body, 0, body.Length, ct).ConfigureAwait(false);
            await _stream.FlushAsync(ct).ConfigureAwait(false);
        }

        private async Task<HttpResponseMessage> ReadResponseAsync(HttpRequestMessage request, CancellationToken ct)
        {
            string statusLine = await ReadLineAsync(ct).ConfigureAwait(false);
            var response = new HttpResponseMessage { Version = HttpVersion.Version11, RequestMessage = request };
            ParseStatusLine(statusLine, response);

            var headers = new List<KeyValuePair<string, string>>();
            bool chunked = false;
            bool responseClose = false;
            long? contentLength = null;

            while (true)
            {
                string line = await ReadLineAsync(ct).ConfigureAwait(false);
                if (line.Length == 0) break;
                int colon = line.IndexOf(':');
                if (colon <= 0) continue;
                string name = line.Substring(0, colon).Trim();
                string value = line.Substring(colon + 1).Trim();

                if (string.Equals(name, "Content-Length", StringComparison.OrdinalIgnoreCase) && long.TryParse(value, out long cl))
                    contentLength = cl;
                else if (string.Equals(name, "Transfer-Encoding", StringComparison.OrdinalIgnoreCase) &&
                         value.IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0)
                    chunked = true;
                else if (string.Equals(name, "Connection", StringComparison.OrdinalIgnoreCase) &&
                         value.IndexOf("close", StringComparison.OrdinalIgnoreCase) >= 0)
                    responseClose = true;

                headers.Add(new KeyValuePair<string, string>(name, value));
            }

            // Responses that by definition carry no body have a determinate (zero-length) end.
            int statusCode = (int)response.StatusCode;
            bool noBodyStatus = statusCode == 204 || statusCode == 304 || (statusCode >= 100 && statusCode < 200);
            if (noBodyStatus && !chunked && !contentLength.HasValue) contentLength = 0;

            // Keep-alive on HTTP/1.1 unless either side asked to close and the body has a determinate end
            // (a read-until-close body forces the connection closed, so it can't be reused).
            bool determinateEnd = chunked || contentLength.HasValue;
            bool keepAlive = response.Version == HttpVersion.Version11 && !responseClose && !RequestWantsClose(request) && determinateEnd;

            byte[] prefix = new byte[_len - _pos];
            Array.Copy(_buf, _pos, prefix, 0, prefix.Length);

            Http1ContentStream bodyStream = null!;
            Action<bool> onDisposed = reusable =>
            {
                // On reuse, hand back any bytes the header read over-read (the next response's start).
                if (reusable) _seed = bodyStream.TakeUnconsumedPrefix();
                if (OnResponseDrained != null) OnResponseDrained(reusable);
                else _owner.Dispose();
            };
            bodyStream = new Http1ContentStream(prefix, _stream, chunked, contentLength, _owner, keepAlive, onDisposed);
            var content = new StreamContent(bodyStream);
            response.Content = content;

            foreach (var kv in headers)
            {
                if (!response.Headers.TryAddWithoutValidation(kv.Key, kv.Value))
                    content.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
            }

            return response;
        }

        private static void ParseStatusLine(string line, HttpResponseMessage response)
        {
            // "HTTP/1.1 200 OK"
            if (line.StartsWith("HTTP/1.0", StringComparison.Ordinal)) response.Version = HttpVersion.Version10;
            int sp1 = line.IndexOf(' ');
            if (sp1 < 0) throw new IOException("Malformed status line: " + line);
            int sp2 = line.IndexOf(' ', sp1 + 1);
            string codeText = sp2 < 0 ? line.Substring(sp1 + 1) : line.Substring(sp1 + 1, sp2 - sp1 - 1);
            if (!int.TryParse(codeText, out int code)) throw new IOException("Malformed status code: " + line);
            response.StatusCode = (HttpStatusCode)code;
            if (sp2 >= 0) response.ReasonPhrase = line.Substring(sp2 + 1);
        }

        private async Task<string> ReadLineAsync(CancellationToken ct)
        {
            var sb = new StringBuilder(64);
            while (true)
            {
                if (_pos >= _len)
                {
                    await FillAsync(ct).ConfigureAwait(false);
                    if (_len == 0) return sb.ToString(); // EOF
                }
                byte b = _buf[_pos++];
                if (b == (byte)'\n')
                {
                    if (sb.Length > 0 && sb[sb.Length - 1] == '\r') sb.Length--;
                    return sb.ToString();
                }
                sb.Append((char)b);
            }
        }

        private async Task FillAsync(CancellationToken ct)
        {
            if (_seed != null)
            {
                _buf = _seed; // adopt the over-read leftover from the previous keep-alive response
                _pos = 0;
                _len = _seed.Length;
                _seed = null;
                return;
            }
            if (_buf.Length < 8192) _buf = new byte[8192]; // we may have adopted a small seed buffer previously
            _pos = 0;
            _len = await _stream.ReadAsync(_buf, 0, _buf.Length, ct).ConfigureAwait(false);
        }

        private static bool IsHost(string name) => string.Equals(name, "Host", StringComparison.OrdinalIgnoreCase);

        private static bool RequestWantsClose(HttpRequestMessage request)
        {
            if (request.Headers.NonValidated.TryGetValues("Connection", out var values))
                foreach (var v in values)
                    if (v.IndexOf("close", StringComparison.OrdinalIgnoreCase) >= 0)
                        return true;
            return false;
        }

        private static string HostHeaderValue(Uri uri, HttpRequestMessage request)
        {
            if (!string.IsNullOrEmpty(request.Headers.Host)) return request.Headers.Host!;
            return uri.IsDefaultPort ? uri.IdnHost : uri.IdnHost + ":" + uri.Port;
        }
    }
}
