package main

import (
	"flag"
	"fmt"
	"github.com/kofemann/nfstop/nfs"
	"github.com/kofemann/nfstop/sniffer"
	"github.com/kofemann/nfstop/stream"
	"github.com/tsg/gopacket"
	"github.com/tsg/gopacket/layers"
	"github.com/tsg/gopacket/pcap"
	"os"
)

const (
	// ANY_DEVICE peseudo interface to listen all interfaces
	ANY_DEVICE = "any"

	// NFS_FILTER default packet fiter to capture nfs traffic
	NFS_FILTER = "port 2049"

	// SNAPLEN packet snapshot length
	SNAPLEN = 65535
)

var streams = make(map[string]*stream.TcpStream)

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

	// Read in packets, pass to assembler.

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

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

			data := tcp.Payload
			if len(data) == 0 {
				continue
			}

			// direction independed unique connection identifier
			connectionKey := fmt.Sprintf("%d:%d",
				packet.NetworkLayer().NetworkFlow().FastHash(),
				tcp.TransportFlow().FastHash(),
			)

			fmt.Printf("%s %d %s:%s -> %s:%s\n",
				packet.Metadata().CaptureInfo.Timestamp,
				counter,
				packet.NetworkLayer().NetworkFlow().Src(),
				tcp.TransportFlow().Src(),
				packet.NetworkLayer().NetworkFlow().Dst(),
				tcp.TransportFlow().Dst(),
			)

			dir := 0
			tcpStream, ok := streams[connectionKey]
			if !ok {
				tcpStream = stream.NewTcpStream(tcp)
				streams[connectionKey] = tcpStream
			} else {
				if tcpStream.SrcPort != tcp.SrcPort {
					dir = 1
				}
			}

			rawStream := tcpStream.Data[dir]
			rawStream.Data = append(rawStream.Data, data...)

			nfs.DataArrieved(rawStream)
		}
	}
}
