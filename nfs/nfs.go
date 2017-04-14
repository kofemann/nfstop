package nfs

import (
	"fmt"
	"time"
)

type NfsRequest struct {
	vers   uint32
	minor  uint32
	proc   uint32
	tag    string
	opcode string
	auth   string
	rtime  time.Time
	ctime  time.Time
	client string
	server string
}

func (nfs *NfsRequest) GetOpCode() string {
	return nfs.opcode
}

func (nfs *NfsRequest) GetVersion() string {
	return fmt.Sprintf("%d.%d", nfs.vers, nfs.minor)
}

func (nfs *NfsRequest) GetResponseTime() time.Duration {
	return nfs.rtime.Sub(nfs.ctime)
}

func (nfs *NfsRequest) GetClient() string {
	return nfs.client
}

func (nfs *NfsRequest) GetServer() string {
	return nfs.server
}

func (nfs *NfsRequest) getRequestInfo(xdr *xdr) {

	switch nfs.vers {
	case 3:
		nfs.opcode = nfs.getV3Opcode(int(nfs.proc))
	case 4:
		switch nfs.proc {
		case 0:
			nfs.opcode = "NULL"
		case 1:
			nfs.tag = string(xdr.getDynamicOpaque())
			nfs.minor = xdr.getUInt()
			nfs.opcode = nfs.findV4MainOpcode(xdr)
		}
	}
}

func (nfs *NfsRequest) getNFSReplyStatus(xdr *xdr) string {
	switch nfs.proc {
	case 0:
		return nfsStatus[0]
	default:
		stat := int(xdr.getUInt())
		return nfsStatus[stat]
	}
}

func (nfs *NfsRequest) String() string {
	return fmt.Sprintf("%s -> %s %s v%d.%d op: %s, srt: %v",
		nfs.client, nfs.server,
		nfs.auth,
		nfs.vers, nfs.minor, nfs.opcode,
		nfs.rtime.Sub(nfs.ctime),
	)
}
