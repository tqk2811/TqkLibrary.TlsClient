using System;
using System.IO;
using System.Text;
using TqkLibrary.TlsClient.Http1;
using Xunit;

namespace TqkLibrary.TlsClient.Tests
{
    public class Http1ContentStreamTests
    {
        // Tiny copy buffer to force many small Read() calls (exercises framing state machine).
        private static string ReadAll(Stream s)
        {
            using var ms = new MemoryStream();
            s.CopyTo(ms, bufferSize: 4);
            return Encoding.ASCII.GetString(ms.ToArray());
        }

        [Fact]
        public void ContentLength_ReadsExactBytes()
        {
            var inner = new MemoryStream(Encoding.ASCII.GetBytes("HELLOWORLD"));
            var s = new Http1ContentStream(Array.Empty<byte>(), inner, chunked: false, contentLength: 5, owner: null);
            Assert.Equal("HELLO", ReadAll(s));
        }

        [Fact]
        public void Prefix_DrainedBeforeInner()
        {
            var prefix = Encoding.ASCII.GetBytes("ABC");
            var inner = new MemoryStream(Encoding.ASCII.GetBytes("DEFGH"));
            var s = new Http1ContentStream(prefix, inner, chunked: false, contentLength: 5, owner: null);
            Assert.Equal("ABCDE", ReadAll(s));
        }

        [Fact]
        public void Chunked_DecodesMultipleChunks()
        {
            const string data = "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
            var s = new Http1ContentStream(Array.Empty<byte>(), new MemoryStream(Encoding.ASCII.GetBytes(data)),
                chunked: true, contentLength: null, owner: null);
            Assert.Equal("Wikipedia", ReadAll(s));
        }

        [Fact]
        public void Chunked_WithPrefixSpanningHeaderAndData()
        {
            // The chunk-size line is split across the prefix and the inner stream.
            var prefix = Encoding.ASCII.GetBytes("3\r\nfo");
            var inner = new MemoryStream(Encoding.ASCII.GetBytes("o\r\n0\r\n\r\n"));
            var s = new Http1ContentStream(prefix, inner, chunked: true, contentLength: null, owner: null);
            Assert.Equal("foo", ReadAll(s));
        }

        [Fact]
        public void UntilClose_ReadsEverything()
        {
            const string data = "until-eof-body";
            var s = new Http1ContentStream(Array.Empty<byte>(), new MemoryStream(Encoding.ASCII.GetBytes(data)),
                chunked: false, contentLength: null, owner: null);
            Assert.Equal(data, ReadAll(s));
        }

        [Fact]
        public void Dispose_DisposesOwner()
        {
            var owner = new FlagDisposable();
            var s = new Http1ContentStream(Array.Empty<byte>(), new MemoryStream(), chunked: false, contentLength: 0, owner: owner);
            s.Dispose();
            Assert.True(owner.Disposed);
        }
    }
}
