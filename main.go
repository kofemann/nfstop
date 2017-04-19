package main

import (
	"container/list"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	ui "github.com/gizak/termui"
	"github.com/kofemann/nfstop/nfs"
	"github.com/kofemann/nfstop/sniffer"
	"github.com/kofemann/nfstop/stream"
	"github.com/kofemann/nfstop/utils"
	"github.com/tsg/gopacket"
	"github.com/tsg/gopacket/layers"
	"github.com/tsg/gopacket/pcap"
)

const (
	// ANY_DEVICE peseudo interface to listen all interfaces
	ANY_DEVICE = "any"

	// NFS_FILTER default packet fiter to capture nfs traffic
	NFS_FILTER = "port 2049"

	// SNAPLEN packet snapshot length
	SNAPLEN = 65535

	REFRESH_TIME = 2
)

var streams = make(map[string]*stream.RpcStream)

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

	refreshValue := REFRESH_TIME
	if len(flag.Args()) > 0 {

		refreshValue, err = strconv.Atoi(flag.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid time value: %v\n", err)
			os.Exit(1)
		}
	}

	refreshTime := time.Second * time.Duration(refreshValue)
	ticker := time.Tick(refreshTime)

	collector := list.New()

	quit := make(chan int)

	// request selection

	ByClient := func(r *nfs.NfsRequest) string {
		return r.GetClient()
	}

	ByServer := func(r *nfs.NfsRequest) string {
		return r.GetServer()
	}

	ByOpCode := func(r *nfs.NfsRequest) string {
		return r.GetOpCode()
	}

	ByUser := func(r *nfs.NfsRequest) string {
		return r.GetCred()
	}

	aggrName := "Client Endpoint"
	selection := ByClient

	// UI
	err = ui.Init()
	if err != nil {
		panic(err)
	}
	defer ui.Close()

	title := ui.NewPar("q: Quit, c/s: by clients/servers, o: by nfs ops, u: by user")
	title.BorderFg = ui.ColorDefault
	title.TextFgColor = ui.ColorDefault
	title.Height = 3

	status := ui.NewPar(fmt.Sprintf("Aggregate every %v by: %s", refreshTime, aggrName))
	status.BorderFg = ui.ColorDefault
	status.TextFgColor = ui.ColorDefault
	status.Height = 3

	lSize := ui.TermHeight() - (status.Height + title.Height)

	labelList := ui.NewList()
	labelList.Border = false
	labelList.Height = lSize
	labelList.ItemFgColor = ui.ColorDefault

	histogramList := ui.NewList()
	histogramList.Border = false
	histogramList.Height = lSize
	histogramList.ItemFgColor = ui.ColorDefault

	valuesList := ui.NewList()
	valuesList.Border = false
	valuesList.Height = lSize
	valuesList.ItemFgColor = ui.ColorDefault

	ui.Body.Rows = make([]*ui.Row, 0)
	ui.Body.AddRows(
		ui.NewRow(
			ui.NewCol(12, 0, title),
		),

		ui.NewRow(
			ui.NewCol(4, 0, labelList),
			ui.NewCol(6, 0, histogramList),
			ui.NewCol(2, 0, valuesList),
		),
		ui.NewRow(
			ui.NewCol(12, 0, status),
		),
	)

	go func() {
		for {
			select {
			case <-quit:
				return
			case <-ticker:
				// time to refresh screen
				l := collector
				collector = list.New()

				term := utils.Aggr(l, selection)
				sum := term.Sum()

				labels := make([]string, l.Len())
				histograms := make([]string, l.Len())
				values := make([]string, l.Len())
				size := (ui.TermWidth() / 12) * 6

				status.Text = fmt.Sprintf("Aggregate every %v by: %s", refreshTime, aggrName)

				for i, e := range term.Elements {
					labels[i] = fmt.Sprintf("%s", e.Key)
					histograms[i] = utils.FillHisto(sum, e.Value, size)
					values[i] = fmt.Sprintf("%8d", e.Value)
				}

				labelList.Items = labels
				histogramList.Items = histograms
				valuesList.Items = values
				ui.Body.Align()
				ui.Render(ui.Body)

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

				dir := 0
				rpcStream, ok := streams[connectionKey]
				if !ok {
					rpcStream = stream.NewRpcStream(tcp)
					streams[connectionKey] = rpcStream
				} else {
					if rpcStream.SrcPort != tcp.SrcPort {
						dir = 1
					}
				}

				event := &stream.StreamEvent{
					Timestamp: packet.Metadata().CaptureInfo.Timestamp,
					Src:       packet.NetworkLayer().NetworkFlow().Src().String(),
					Dst:       packet.NetworkLayer().NetworkFlow().Dst().String(),
					SrcPort:   tcp.TransportFlow().Src().String(),
					DstPort:   tcp.TransportFlow().Dst().String(),
					Stream:    rpcStream,
				}

				rawStream := rpcStream.Data[dir]
				rawStream.Data = append(rawStream.Data, data...)

				nfs.DataArrieved(rawStream, event, collector)
			}
		}
	}()

	ui.Handle("/sys/kbd/s", func(ui.Event) {
		selection = ByServer
		aggrName = "Server Endpoint"
	})

	ui.Handle("/sys/kbd/o", func(ui.Event) {
		selection = ByOpCode
		aggrName = "NFS operation"
	})

	ui.Handle("/sys/kbd/c", func(ui.Event) {
		selection = ByClient
		aggrName = "Client Endpoint"
	})

	ui.Handle("/sys/kbd/u", func(ui.Event) {
		selection = ByUser
		aggrName = "User Credential"
	})

	ui.Handle("/sys/kbd/q", func(ui.Event) {
		ui.StopLoop()
		quit <- 1
	})

	ui.Handle("/sys/wnd/resize", func(e ui.Event) {
		lSize = ui.TermHeight() - (status.Height + title.Height)
		labelList.Height = lSize
		histogramList.Height = lSize
		valuesList.Height = lSize

		ui.Body.Width = ui.TermWidth()
		ui.Body.Align()
		ui.Clear()
		ui.Render(ui.Body)
	})

	ui.Body.Align()
	ui.Render(ui.Body)

	ui.Loop()
}
