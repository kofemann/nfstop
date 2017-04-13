package nfs

import (
	"github.com/kofemann/nfstop/stream"
	"github.com/kofemann/nfstop/utils"
)

const (
	rpcLastFrag = 0x80000000
	rpcSizeMask = 0x7fffffff
)

const (
	rpcCall  = 0
	rpcReply = 1
)

func DataArrieved(s *stream.Stream) {

	for len(s.Data) > 0 {

		if len(s.Data) < 4 {
			return
		}

		fragmentSize := len(s.Data)
		utils.DumpAsHex(s.Data)

		s.Data = s.Data[fragmentSize:]
	}

}
