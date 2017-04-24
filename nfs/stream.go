package nfs

import (
	"container/list"
	"encoding/binary"
	"strings"
	"time"

	ftrace "github.com/kofemann/linux_ftrace"
	"github.com/patrickmn/go-cache"
	"github.com/tsg/gopacket"
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

func (rs *RpcStream) PacketArrieved(packet gopacket.Packet) *list.List {

	l := list.New()
	tcp := packet.TransportLayer().(*layers.TCP)
	data := tcp.Payload

	if len(data) == 0 {
		return l
	}

	dir := 0
	if rs.SrcPort != tcp.SrcPort {
		dir = 1
	}

	s := rs.Data[dir]
	s.Data = append(s.Data, data...)

	event := &StreamEvent{
		Timestamp: packet.Metadata().CaptureInfo.Timestamp,
		Src:       packet.NetworkLayer().NetworkFlow().Src().String(),
		Dst:       packet.NetworkLayer().NetworkFlow().Dst().String(),
		SrcPort:   tcp.TransportFlow().Src().String(),
		DstPort:   tcp.TransportFlow().Dst().String(),
		Stream:    rs,
	}

	for len(s.Data) > 0 {

		if len(s.Data) < 4 {
			break
		}

		marker := uint32(binary.BigEndian.Uint32(s.Data[0:4]))

		islast := (marker & rpcLastFrag) != 0
		if !islast {
			// FIXME: we need to assemple all fragments
			break
		}

		size := int(marker & rpcSizeMask)
		if size > len(s.Data)-4 {
			// not all data arraived
			break
		}

		data := s.Data[4 : 4+size]
		xdr := newXDR(data)

		r := procesRpcMessage(xdr, event)
		if r != nil {
			pid, ok := xidCache.Get(r.xid)
			if ok {
				xidCache.Delete(r.xid)
				r.pid = pid.(int)
			}
			l.PushBack(r)
		}

		s.Data = s.Data[4+size:]
	}

	return l
}

var xidCache = cache.New(time.Minute*1, time.Minute*1)

var enablePidTracing = false
var pidSource chan ftrace.Trace
var eventTrace *ftrace.EventTrace

func EnablePidTracing() {

	enablePidTracing = true
	eventTrace = ftrace.NewEventTrace("sunrpc/xprt_transmit")
	eventTrace.Enable()

	pidSource = eventTrace.EventSource()
	go func() {
		for {
			select {
			case trace, ok := <-pidSource:
				if !ok {
					return
				}
				xid := strings.Split(trace.Event, " ")[1][6:]
				l := len(xid)
				if l < 8 {
					xid = strings.Repeat("0", 8-l) + xid
				}
				xidCache.SetDefault(xid, trace.Pid)
			}
		}
	}()
}

func DisablePidTracing() {
	if enablePidTracing {
		eventTrace.Disable()
	}
}
