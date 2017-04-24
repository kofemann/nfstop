package nfs

import (
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
		pid:    -1,
		xid:    xid,
	}

	r.getRequestInfo(xdr)

	event.Stream.PendingRequests.SetDefault(xid, r)
}

func handleReply(xid string, xdr *xdr, event *StreamEvent) *NfsRequest {

	var r *NfsRequest
	if x, ok := event.Stream.PendingRequests.Get(xid); ok {
		event.Stream.PendingRequests.Delete(xid)
		r = x.(*NfsRequest)
		r.rtime = event.Timestamp

		return r
	}
	return nil
}

func procesRpcMessage(xdr *xdr, event *StreamEvent) *NfsRequest {

	xid := fmt.Sprintf("%.8x", xdr.getUInt())
	msgType := xdr.getUInt()
	switch msgType {
	case rpcCall:
		handleCall(xid, xdr, event)
		return nil
	case rpcReply:
		return handleReply(xid, xdr, event)
	default:
		// bad xdr
		return nil
	}
}
