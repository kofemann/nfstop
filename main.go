package main

import (
	"flag"
	"fmt"
	"github.com/tsg/gopacket"
	"os"
	"syscall"
	//	"github.com/tsg/gopacket/layers"
	"github.com/kofemann/nfstop/sniffer"
	"github.com/tsg/gopacket/pcap"
)

const (
	// ANY_DEVICE peseudo interface to listen all interfaces
	ANY_DEVICE = "any"

	// NFS_FILTER default packet fiter to capture nfs traffic
	NFS_FILTER = "port 2049"
)

type NopWorker struct{}

func (w *NopWorker) OnPacket(data []byte, ci *gopacket.CaptureInfo) {

}

var iface = flag.String("i", ANY_DEVICE, "name of `interface` to listen")
var filter = flag.String("f", NFS_FILTER, "capture `filter` in libpcap filter syntax")

func main() {

	flag.Parse()

	sniffer := &sniffer.Sniffer{
		Interface: *iface,
		Filter:    *filter,
		Worker:    &NopWorker{},
	}
	counter := 0

	err := sniffer.Init()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize sniffer: %v\n", err)
		os.Exit(1)
	}

	isDone := false
	for !isDone {

		data, ci, err := sniffer.DataSource.ReadPacketData()

		if err == pcap.NextErrorTimeoutExpired || err == syscall.EINTR {
			// no packet received
			continue
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Sniffing error: %s\n", err)
			isDone = true
			continue
		}

		if len(data) == 0 {
			// Empty packet, probably timeout from afpacket
			continue
		}

		counter++
		fmt.Printf("Packet number: %d\n", counter)

		sniffer.Worker.OnPacket(data, &ci)
	}
}
