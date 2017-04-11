package nfs

import (
	"bufio"

	"io"
	"log"
	"net/http"

	"github.com/tsg/gopacket"
	"github.com/tsg/gopacket/tcpassembly"
	"github.com/tsg/gopacket/tcpassembly/tcpreader"
)

// Build a simple RPC request parser using tcpassembly.StreamFactory and tcpassembly.Stream interfaces

// RpcStreamFactory implements tcpassembly.StreamFactory
type RpcStreamFactory struct{}

// rpcStream will handle the actual decoding of http requests.
type rpcStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (rs *RpcStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	rstream := &rpcStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go rstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &rstream.r
}

func (rs *rpcStream) run() {
	buf := bufio.NewReader(&rs.r)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", rs.net, rs.transport, ":", err)
		} else {
			bodyBytes := tcpreader.DiscardBytesToEOF(req.Body)
			req.Body.Close()
			log.Println("Received request from stream", rs.net, rs.transport, ":", req, "with", bodyBytes, "bytes in request body")
		}
	}
}
