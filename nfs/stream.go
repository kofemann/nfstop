package nfs

import (
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/tsg/gopacket/layers"
)

type Stream struct {
	Data []byte
}

type RpcStream struct {
	SrcPort, DstPort layers.TCPPort
	Dir              int
	Data             [](*Stream)
	PendingRequests  *cache.Cache
}

func NewRpcStream(tcp *layers.TCP) *RpcStream {

	in := Stream{Data: make([]byte, 0)}
	out := Stream{Data: make([]byte, 0)}
	c := cache.New(time.Minute*2, time.Minute*5)
	d := [](*Stream){&in, &out}
	return &RpcStream{Dir: 0,
		SrcPort:         tcp.SrcPort,
		DstPort:         tcp.DstPort,
		Data:            d,
		PendingRequests: c,
	}
}
