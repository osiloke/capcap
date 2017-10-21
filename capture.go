package capcap

import (
	"fmt"
	"io"
	"log"
	"runtime"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	MAX_ETHERNET_MTU       = 9216
	MINIMUM_IP_PACKET_SIZE = 58
	LARGE_FLOW_SIZE        = 1024 * 1024 * 1024 * 1 //4 GB
)

type trackedFlow struct {
	packets   uint
	bytecount uint
	last      time.Time
	logged    bool
}

func (t trackedFlow) String() string {
	return fmt.Sprintf("packets=%d bytecount=%d last=%s", t.packets, t.bytecount, t.last)
}

type PcapFrame struct {
	ci   gopacket.CaptureInfo
	data []byte
}

type FiveTuple struct {
	proto         layers.IPProtocol
	networkFlow   gopacket.Flow
	transportFlow gopacket.Flow
}

func (f FiveTuple) String() string {
	src, dst := f.networkFlow.Endpoints()
	sport, dport := f.transportFlow.Endpoints()
	return fmt.Sprintf("src=%s sport=%s dst=%s dport=%s", src, sport, dst, dport)
}

func mustAtoiWithDefault(s string, defaultValue int) int {
	if s == "" {
		return defaultValue
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		log.Fatal(err)
	}
	return i
}

func doSniff(intf string, worker int, writerchan chan PcapFrame, conf *Conf) {
	runtime.LockOSThread()
	var (
		// metricsAddress = conf.MetricsAddress

		// iface              = conf.Iface
		filter             = conf.Filter
		packetTimeInterval = conf.PacketTimeInterval
		flowTimeout        = conf.FlowTimeout
		flowByteCutoff     = conf.FlowByteCutoff
		flowPacketCutoff   = conf.FlowPacketCutoff
		// writeOutputPath    = conf.WriteOutputPath
		// writeCompressed    = conf.WriteCompressed
		// rotationInterval   = conf.RotationInterval
	)

	log.Printf("Starting worker %d on interface %s", worker, intf)
	// workerString := fmt.Sprintf("%d", worker)

	var err error
	handle, err := pcap.OpenLive(intf, MAX_ETHERNET_MTU, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	err = handle.SetBPFFilter(filter)
	if err != nil { // optional
		panic(err)
	}

	seen := make(map[FiveTuple]*trackedFlow)
	var totalFlows, removedFlows, totalBytes, outputBytes, totalPackets, outputPackets uint
	var pcapStats *pcap.Stats
	lastcleanup := time.Now()

	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &dot1q, &ip4, &ip6, &tcp, &udp)
	parser.IgnoreUnsupported = true
	decoded := []gopacket.LayerType{}
	var speedup int
	for {
		packetData, ci, err := handle.ZeroCopyReadPacketData()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err)
		}
		totalPackets += 1
		totalBytes += uint(len(packetData))

		err = parser.DecodeLayers(packetData, &decoded)
		var flow FiveTuple
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv6:
				flow.proto = ip6.NextHeader
				flow.networkFlow = ip6.NetworkFlow()
			case layers.LayerTypeIPv4:
				flow.proto = ip4.Protocol
				flow.networkFlow = ip4.NetworkFlow()
				//log.Println(worker, ip4.SrcIP, ip4.DstIP)
			case layers.LayerTypeUDP:
				flow.transportFlow = udp.TransportFlow()
			case layers.LayerTypeTCP:
				flow.transportFlow = tcp.TransportFlow()
			}
		}

		flw := seen[flow]
		if flw == nil {
			flw = &trackedFlow{}
			seen[flow] = flw
			//log.Println("NEW", flw, flow)
			totalFlows += 1
		}
		flw.last = time.Now()
		flw.packets += 1
		pl := uint(len(packetData))
		if pl > MINIMUM_IP_PACKET_SIZE {
			flw.bytecount += pl - MINIMUM_IP_PACKET_SIZE
		}
		if flw.bytecount < flowByteCutoff && flw.packets < flowPacketCutoff {
			//log.Println(flow, flw, "continues")
			outputPackets += 1
			outputBytes += uint(len(packetData))

			packetDataCopy := make([]byte, len(packetData))
			copy(packetDataCopy, packetData)

			writerchan <- PcapFrame{ci, packetDataCopy}
		} else if flw.logged == false && flw.bytecount > LARGE_FLOW_SIZE {
			log.Printf("Large flow over 8GB: %s", flow)
			flw.logged = true
		}
		//Cleanup
		speedup++
		if speedup == 5000 {
			speedup = 0
			pcapStats, err = handle.Stats()
			if err != nil {
				log.Fatal(err)
			}
			if time.Since(lastcleanup) > packetTimeInterval {
				lastcleanup = time.Now()
				//seen = make(map[string]*trackedFlow)
				var remove []FiveTuple
				for flow, flw := range seen {
					if lastcleanup.Sub(flw.last) > flowTimeout {
						remove = append(remove, flow)
						removedFlows += 1
						// mFlowSize.Observe(float64(flw.bytecount))
					}
				}
				for _, rem := range remove {
					delete(seen, rem)
				}
				log.Printf("if=%s W=%02d flows=%d removed=%d bytes=%d pkts=%d output=%d outpct=%.1f recvd=%d dropped=%d ifdropped=%d",
					intf, worker, len(seen), len(remove),
					totalBytes, totalPackets, outputPackets, 100*float64(outputPackets)/float64(totalPackets),
					pcapStats.PacketsReceived, pcapStats.PacketsDropped, pcapStats.PacketsIfDropped)

				// expireSeconds := float64(time.Since(lastcleanup).Seconds())
				// mExpired.WithLabelValues(intf, workerString).Set(float64(len(remove)))
				// mExpiredDurTotal.WithLabelValues(intf, workerString).Add(expireSeconds)
			}
			// mActiveFlows.WithLabelValues(intf, workerString).Set(float64(len(seen)))

			// mFlows.WithLabelValues(intf, workerString).Add(float64(totalFlows))
			totalFlows = 0

			// mPackets.WithLabelValues(intf, workerString).Add(float64(totalPackets))
			totalPackets = 0

			// mBytes.WithLabelValues(intf, workerString).Add(float64(totalBytes))
			totalBytes = 0

			// mBytesOutput.WithLabelValues(intf, workerString).Add(float64(outputBytes))
			outputBytes = 0

			// mOutput.WithLabelValues(intf, workerString).Add(float64(outputPackets))
			outputPackets = 0

			// mReceived.WithLabelValues(intf, workerString).Set(float64(pcapStats.PacketsReceived))
			// mDropped.WithLabelValues(intf, workerString).Set(float64(pcapStats.PacketsDropped))
			// mIfDropped.WithLabelValues(intf, workerString).Set(float64(pcapStats.PacketsIfDropped))
		}
	}
}
