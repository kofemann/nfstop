package stream

import (
	"fmt"
	"time"
)

type Event struct {
	Timestamp time.Time
	Src       string
	Dst       string
	SrcPort   string
	DstPort   string
	Stream    *TcpStream
}

func (e *Event) String() string {
	return fmt.Sprintf("%v %s:%s -> %s:%s",
		e.Timestamp,
		e.Src,
		e.SrcPort,
		e.Dst,
		e.DstPort,
	)
}
