package stream

import (
	"github.com/patrickmn/go-cache"
	"github.com/tsg/gopacket/layers"
	"time"
)

type Stream struct {
	Data []byte
}

type TcpStream struct {
	SrcPort, DstPort layers.TCPPort
	Dir              int
	Data             [](*Stream)
	Cache            *cache.Cache
}

func NewTcpStream(tcp *layers.TCP) *TcpStream {

	in := Stream{Data: make([]byte, 0)}
	out := Stream{Data: make([]byte, 0)}
	c := cache.New(time.Minute*2, time.Minute*5)
	d := [](*Stream){&in, &out}
	return &TcpStream{Dir: 0,
		SrcPort: tcp.SrcPort,
		DstPort: tcp.DstPort,
		Data:    d,
		Cache:   c,
	}
}
