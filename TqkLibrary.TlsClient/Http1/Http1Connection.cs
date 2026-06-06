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
    /// <see cref="Http1ContentStream"/>. One request per connection (no pooling yet).
    /// </summary>
    internal sealed class Http1Connection
    {
        private readonly Stream _stream;
        private readonly IDisposable _owner;
        private readonly byte[] _buf = new byte[8192];
        private int _pos;
        private int _len;

        /// <param name="stream">Plaintext stream (e.g. an authenticated <c>ImpersonatedTlsStream</c>).</param>
        /// <param name="owner">Disposed when the response body is disposed (the TLS connection + transport).</param>
        public Http1Connection(Stream stream, IDisposable owner)
        {
            _stream = stream;
            _owner = owner;
        }

        public async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
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

            foreach (var header in request.Headers)
            {
                if (IsHost(header.Key) || IsConnection(header.Key)) continue;
                foreach (var value in header.Value)
                    sb.Append(header.Key).Append(": ").Append(value).Append("\r\n");
            }

            if (request.Content != null)
            {
                foreach (var header in request.Content.Headers)
                {
                    if (string.Equals(header.Key, "Content-Length", StringComparison.OrdinalIgnoreCase)) continue;
                    foreach (var value in header.Value)
                        sb.Append(header.Key).Append(": ").Append(value).Append("\r\n");
                }
                sb.Append("Content-Length: ").Append(body!.Length).Append("\r\n");
            }

            // No connection pooling yet: ask the server to close so until-close framing terminates.
            sb.Append("Connection: close\r\n\r\n");

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

                headers.Add(new KeyValuePair<string, string>(name, value));
            }

            byte[] prefix = new byte[_len - _pos];
            Array.Copy(_buf, _pos, prefix, 0, prefix.Length);

            var bodyStream = new Http1ContentStream(prefix, _stream, chunked, contentLength, _owner);
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
            _pos = 0;
            _len = await _stream.ReadAsync(_buf, 0, _buf.Length, ct).ConfigureAwait(false);
        }

        private static bool IsHost(string name) => string.Equals(name, "Host", StringComparison.OrdinalIgnoreCase);
        private static bool IsConnection(string name) => string.Equals(name, "Connection", StringComparison.OrdinalIgnoreCase);

        private static string HostHeaderValue(Uri uri, HttpRequestMessage request)
        {
            if (!string.IsNullOrEmpty(request.Headers.Host)) return request.Headers.Host!;
            return uri.IsDefaultPort ? uri.IdnHost : uri.IdnHost + ":" + uri.Port;
        }
    }
}
