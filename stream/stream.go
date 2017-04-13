package stream

import (
	"github.com/tsg/gopacket/layers"
)

type Stream struct {
	Data []byte
}

type TcpStream struct {
	SrcPort, DstPort layers.TCPPort
	Dir              int
	Data             [](*Stream)
}

func NewTcpStream(tcp *layers.TCP) *TcpStream {

	in := Stream{Data: make([]byte, 0)}
	out := Stream{Data: make([]byte, 0)}
	d := [](*Stream){&in, &out}
	return &TcpStream{Dir: 0,
		SrcPort: tcp.SrcPort,
		DstPort: tcp.DstPort,
		Data:    d,
	}
}
