package nfs

import (
	"fmt"
	"time"
)

type StreamEvent struct {
	Timestamp time.Time
	Src       string
	Dst       string
	SrcPort   string
	DstPort   string
	Stream    *RpcStream
}

func (e *StreamEvent) String() string {
	return fmt.Sprintf("%v %s:%s -> %s:%s",
		e.Timestamp,
		e.Src,
		e.SrcPort,
		e.Dst,
		e.DstPort,
	)
}
