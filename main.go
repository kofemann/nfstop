package main

import (
	"flag"
	"fmt"
	"github.com/kofemann/nfstop/nfs"
	"github.com/kofemann/nfstop/sniffer"
	"github.com/tsg/gopacket"
	"github.com/tsg/gopacket/layers"
	"github.com/tsg/gopacket/pcap"
	"github.com/tsg/gopacket/tcpassembly"
	"os"
	"time"
)

const (
	// ANY_DEVICE peseudo interface to listen all interfaces
	ANY_DEVICE = "any"

	// NFS_FILTER default packet fiter to capture nfs traffic
	NFS_FILTER = "port 2049"

	// SNAPLEN packet snapshot length
	SNAPLEN = 65535
)

var iface = flag.String("i", ANY_DEVICE, "name of `interface` to listen")
var filter = flag.String("f", NFS_FILTER, "capture `filter` in libpcap filter syntax")
var listInterfaces = flag.Bool("D", false, "print list of interfaces and exit")
var snaplen = flag.Int("s", SNAPLEN, "packet `snaplen` - snapshot length")

func main() {

	flag.Parse()

	if *listInterfaces {
		ifaces, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get list of interfaces: %v\n", err)
			os.Exit(1)
		}

		for i, dev := range ifaces {
			fmt.Printf("%d. %s\n", i+1, dev.Name)
		}
		os.Exit(0)
	}

	sniffer := &sniffer.Sniffer{
		Interface: *iface,
		Filter:    *filter,
		Snaplen:   *snaplen,
	}

	handle, err := sniffer.Init()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize sniffer: %v\n", err)
		os.Exit(1)
	}

	streamFactory := &nfs.RpcStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// Read in packets, pass to assembler.

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)

	counter := 0

	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				os.Exit(0)
			}
			counter++
			//		log.Println(packet)
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {

				continue
			}

			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

			fmt.Println(packet.NetworkLayer().NetworkFlow())
			fmt.Printf("%d %s:%s -> %s:%s\n", counter,
				packet.NetworkLayer().NetworkFlow().Src(),
				tcp.TransportFlow().Src(),
				packet.NetworkLayer().NetworkFlow().Dst(),
				tcp.TransportFlow().Dst(),
			)

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}
