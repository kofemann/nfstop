package nfs

import (
	"container/list"
	"encoding/binary"
	"fmt"
)

const (
	rpcLastFrag = 0x80000000
	rpcSizeMask = 0x7fffffff
)

const (
	rpcCall  = 0
	rpcReply = 1
)

const nfsProgramNumber = 100003

func handleCall(xid string, xdr *xdr, event *StreamEvent) {

	// eat rpc version number
	xdr.getUInt()

	rpcProg := xdr.getUInt()
	if rpcProg != nfsProgramNumber {
		// not a NFS request
		return
	}

	nfsVers := xdr.getUInt()
	nfsProc := xdr.getUInt()

	authFlavor := xdr.getUInt()
	authOpaque := xdr.getDynamicOpaque()
	var auth string
	switch authFlavor {
	case 0:
		auth = "none"
	case 1:
		//auth = "unix"
		credXdr := makeXDR(authOpaque)
		// stamp
		credXdr.getUInt()
		// machine
		credXdr.getString()
		// uid
		uid := credXdr.getUInt()
		// gid
		credXdr.getUInt()
		// gids
		credXdr.getUIntVector()
		auth = fmt.Sprintf("%d", uid)
	case 6:
		auth = "rpcsec_gss"
	default:
		auth = fmt.Sprintf("unknown (%d)", authFlavor)
	}

	// eat auth verifier
	xdr.getUInt()
	xdr.getDynamicOpaque()

	r := &NfsRequest{
		vers:   nfsVers,
		proc:   nfsProc,
		auth:   auth,
		ctime:  event.Timestamp,
		client: event.Src + ":" + event.SrcPort,
		server: event.Dst + ":" + event.DstPort,
	}

	r.getRequestInfo(xdr)

	event.Stream.PendingRequests.SetDefault(xid, r)
}

func handleReply(xid string, xdr *xdr, event *StreamEvent, l *list.List) {

	var r *NfsRequest
	if x, ok := event.Stream.PendingRequests.Get(xid); ok {
		event.Stream.PendingRequests.Delete(xid)
		r = x.(*NfsRequest)
		r.rtime = event.Timestamp

		l.PushBack(r)
	}

	replyStatus := xdr.getUInt()
	// we are interested only in accepted rpc reply
	if replyStatus != 0 {
		return
	}
}

func procesRpcMessage(xdr *xdr, event *StreamEvent, l *list.List) {

	xid := fmt.Sprintf("%.8x", xdr.getUInt())
	msgType := xdr.getUInt()
	switch msgType {
	case rpcCall:
		handleCall(xid, xdr, event)
	case rpcReply:
		handleReply(xid, xdr, event, l)
	default:
		// bad xdr

	}
}

func DataArrieved(s *Stream, event *StreamEvent, l *list.List) {

	for len(s.Data) > 0 {

		if len(s.Data) < 4 {
			return
		}

		marker := uint32(binary.BigEndian.Uint32(s.Data[0:4]))

		islast := (marker & rpcLastFrag) != 0
		if !islast {
			// FIXME: we need to assemple all fragments
			return
		}

		size := int(marker & rpcSizeMask)
		if size > len(s.Data)-4 {
			// not all data arraived
			return
		}

		data := s.Data[4 : 4+size]
		xdr := newXDR(data)

		procesRpcMessage(xdr, event, l)
		s.Data = s.Data[4+size:]
	}

}
