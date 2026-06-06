// Package main builds a c-shared library exposing a pure TLS codec over uTLS.
// The transport (TCP/proxy) is owned by the caller (C#); Go reads/writes ciphertext
// through C callbacks (a callback-backed net.Conn) and exposes plaintext via TlsRead/TlsWrite.
package main

/*
#include "bridge.h"
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"io"
	"net"
	"sync"
	"time"
	"unsafe"

	"tqktls/internal/codec"

	utls "github.com/refraction-networking/utls"
)

// callbackConn is a net.Conn whose I/O is delegated to C# via C function pointers.
type callbackConn struct {
	readCb  C.tqk_read_cb
	writeCb C.tqk_write_cb
	closeCb C.tqk_close_cb
	ctx     unsafe.Pointer
}

func (c *callbackConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := int(C.tqk_call_read(c.readCb, c.ctx, (*C.uint8_t)(unsafe.Pointer(&p[0])), C.int(len(p))))
	if n > 0 {
		return n, nil
	}
	if n == 0 {
		return 0, io.EOF
	}
	return 0, io.ErrUnexpectedEOF
}

func (c *callbackConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := int(C.tqk_call_write(c.writeCb, c.ctx, (*C.uint8_t)(unsafe.Pointer(&p[0])), C.int(len(p))))
	if n < 0 {
		return 0, io.ErrClosedPipe
	}
	if n < len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

func (c *callbackConn) Close() error {
	C.tqk_call_close(c.closeCb, c.ctx)
	return nil
}

func (c *callbackConn) LocalAddr() net.Addr                { return tqkAddr{} }
func (c *callbackConn) RemoteAddr() net.Addr               { return tqkAddr{} }
func (c *callbackConn) SetDeadline(t time.Time) error      { return nil }
func (c *callbackConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *callbackConn) SetWriteDeadline(t time.Time) error { return nil }

type tqkAddr struct{}

func (tqkAddr) Network() string { return "tqktls" }
func (tqkAddr) String() string  { return "tqktls" }

type connEntry struct {
	opts  codec.Options
	cb    *callbackConn
	uconn *utls.UConn
}

var (
	regMu  sync.Mutex
	regSeq int64
	reg    = make(map[int64]*connEntry)
)

func lookup(id int64) *connEntry {
	regMu.Lock()
	defer regMu.Unlock()
	return reg[id]
}

//export TlsNew
func TlsNew(optsJSON *C.char, readCb C.tqk_read_cb, writeCb C.tqk_write_cb, closeCb C.tqk_close_cb, ctx unsafe.Pointer) C.longlong {
	var opts codec.Options
	if err := json.Unmarshal([]byte(C.GoString(optsJSON)), &opts); err != nil {
		return -1
	}
	e := &connEntry{
		opts: opts,
		cb:   &callbackConn{readCb: readCb, writeCb: writeCb, closeCb: closeCb, ctx: ctx},
	}
	regMu.Lock()
	regSeq++
	id := regSeq
	reg[id] = e
	regMu.Unlock()
	return C.longlong(id)
}

// TlsHandshake returns nil on success, or a C string with the error (caller frees via TlsFreeString).
//
//export TlsHandshake
func TlsHandshake(id C.longlong) *C.char {
	e := lookup(int64(id))
	if e == nil {
		return C.CString("invalid handle")
	}
	uconn, err := codec.DialTLS(e.cb, &e.opts)
	if err != nil {
		return C.CString(err.Error())
	}
	e.uconn = uconn
	return nil
}

// TlsRead returns bytes read (>0), 0 on EOF, or -1 on error.
//
//export TlsRead
func TlsRead(id C.longlong, buf *C.uint8_t, length C.int) C.int {
	e := lookup(int64(id))
	if e == nil || e.uconn == nil {
		return -1
	}
	p := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(length))
	n, err := e.uconn.Read(p)
	if n > 0 {
		return C.int(n)
	}
	if err == io.EOF {
		return 0
	}
	if err != nil {
		return -1
	}
	return 0
}

// TlsWrite returns bytes written, or -1 on error.
//
//export TlsWrite
func TlsWrite(id C.longlong, buf *C.uint8_t, length C.int) C.int {
	e := lookup(int64(id))
	if e == nil || e.uconn == nil {
		return -1
	}
	p := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(length))
	n, err := e.uconn.Write(p)
	if err != nil && n == 0 {
		return -1
	}
	return C.int(n)
}

// TlsGetAlpn returns the negotiated ALPN protocol (caller frees via TlsFreeString).
//
//export TlsGetAlpn
func TlsGetAlpn(id C.longlong) *C.char {
	e := lookup(int64(id))
	if e == nil || e.uconn == nil {
		return C.CString("")
	}
	return C.CString(e.uconn.ConnectionState().NegotiatedProtocol)
}

//export TlsClose
func TlsClose(id C.longlong) {
	regMu.Lock()
	e := reg[int64(id)]
	delete(reg, int64(id))
	regMu.Unlock()
	if e == nil {
		return
	}
	if e.uconn != nil {
		_ = e.uconn.Close()
	} else if e.cb != nil {
		_ = e.cb.Close()
	}
}

//export TlsFreeString
func TlsFreeString(s *C.char) {
	C.free(unsafe.Pointer(s))
}

func main() {}
