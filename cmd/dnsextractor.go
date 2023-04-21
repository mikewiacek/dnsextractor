package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"strings"
	"time"
)

var (
	iface           = flag.String("i", "eth0", "Interface to read packets from")
	fname           = flag.String("r", "", "Filename to read from, overrides -i")
	snaplen         = flag.Int("s", 65536, "Snap length (number of bytes max to read per packet")
	tstype          = flag.String("timestamp_type", "", "Type of timestamps to use")
	promisc         = flag.Bool("promisc", true, "Set promiscuous mode")
	decoder         = flag.String("decoder", "Ethernet", "Name of the decoder to use")
	lazy            = flag.Bool("lazy", false, "If true, do lazy decoding")
	num_go_routines = flag.Int("ng", 512, "Number of go routine workers to prelaunch.")
)

type RawPacket struct {
	Data        []byte
	CaptureInfo gopacket.CaptureInfo
}

func extractDnsFromRawPacket(chan_num int, ch chan RawPacket) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var dns layers.DNS

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &dns)

	decoded := make([]gopacket.LayerType, 0, 10)

	// Now iterate over the channel looking for new RawPacket objects.
	for raw_packet := range ch {
		start_time := time.Now()

		// Timestamp on this packet.
		_ = raw_packet.CaptureInfo.Timestamp.UnixNano()

		if err := parser.DecodeLayers(raw_packet.Data, &decoded); err != nil {
			continue
		} else if len(decoded) > 0 && decoded[len(decoded)-1] != layers.LayerTypeDNS {
			continue
		}

		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeEthernet:
				// Do nothing.
			case layers.LayerTypeIPv6:
				fmt.Println("IP6 ", ip6.SrcIP, ip6.DstIP)
			case layers.LayerTypeIPv4:
				fmt.Println("IP4 ", ip4.SrcIP, ip4.DstIP, " TTL ", ip4.TTL)
			case layers.LayerTypeUDP:
				fmt.Println("  UDP ", udp.SrcPort, udp.DstPort)
			case layers.LayerTypeTCP:
				fmt.Println("  TCP ", tcp.SrcPort, tcp.DstPort)
			case layers.LayerTypeDNS:
				for i, val := range dns.Questions {
					fmt.Printf("    Question[%d] of type %d class %d for name: %s\n", i, val.Type, val.Class, string(val.Name))
				}

				// TODO(mike):	Large responses will overflow and result in a TCP connection.
				//		Currently we fail to parse these TCP DNS packet.
				for i, val := range dns.Answers {
					fmt.Printf("    Answer[%d] ", i)
					switch val.Type {
					case layers.DNSTypeA:
						fmt.Printf("A %s, %s\n", string(val.Name), val.IP.String())
					case layers.DNSTypeAAAA:
						fmt.Printf("AAAA %s, %s\n", string(val.Name), val.IP.String())
					case layers.DNSTypePTR:
						fmt.Printf("PTR %s, %s\n", string(val.Name), string(val.PTR))
					case layers.DNSTypeCNAME:
						fmt.Printf("CNAME %s, %s\n", string(val.Name), string(val.CNAME))
					case layers.DNSTypeNS:
						fmt.Printf("NS %s, %s\n", string(val.Name), string(val.NS))
					case layers.DNSTypeMX:
						fmt.Printf("MX %s, %s, pref:%d\n", string(val.Name), string(val.MX.Name), val.MX.Preference)
					default:
						fmt.Printf("Unknown return packet with answers type: %d and name: %s\n", val.Type, string(val.Name))
					}
				}

				for _, val := range dns.Authorities {
					switch val.Type {
					case layers.DNSTypeSOA:
						fmt.Printf("    Inbound SOA %s, %s\n", string(val.Name), string(val.SOA.MName))
					default:
						fmt.Printf("    Unknown authorities type: %d\n", val.Type)
					}
				}
			default:
				fmt.Printf("Unknown layer: %v\n decoded len %d\n", layerType, len(decoded))
			}
		}

		elapsed_time := time.Since(start_time)
		fmt.Printf("  ProcessedIn: %d ns\n\n", elapsed_time.Nanoseconds())
	}
}

func ProcessPcapPackets(handle *pcap.Handle, callback func(int, chan RawPacket)) {
	if !flag.Parsed() {
		log.Fatalln("ProcessPcapPackets() called without flag.Parse() being called")
	}

	ch := make(chan RawPacket)
	for i := 0; i < *num_go_routines; i++ {
		go callback(i, ch)
	}

	fmt.Fprintln(os.Stderr, "Starting to read packets")

	for {
		data, captureinfo, err := handle.ReadPacketData()
		if err != nil {
			return
		} else {
			ch <- RawPacket{data, captureinfo}
		}
	}
}

func main() {
	flag.Parse()

	var handle *pcap.Handle
	var err error
	if *fname != "" {
		if handle, err = pcap.OpenOffline(*fname); err != nil {
			log.Fatal("PCAP OpenOffline error:", err)
		}
	} else {
		inactive, err := pcap.NewInactiveHandle(*iface)
		if err != nil {
			log.Fatal("could not create: %v", err)
		}
		defer inactive.CleanUp()

		if err = inactive.SetSnapLen(*snaplen); err != nil {
			log.Fatal("could not set snap length: %v", err)
		} else if err = inactive.SetPromisc(*promisc); err != nil {
			log.Fatal("could not set promisc mode: %v", err)
		} else if err = inactive.SetTimeout(time.Second); err != nil {
			log.Fatal("could not set timeout: %v", err)
		}
		if *tstype != "" {
			if t, err := pcap.TimestampSourceFromString(*tstype); err != nil {
				log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
			} else if err := inactive.SetTimestampSource(t); err != nil {
				log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
			}
		}
		if handle, err = inactive.Activate(); err != nil {
			log.Fatal("PCAP Activate error:", err)
		}
		defer handle.Close()
		if len(flag.Args()) > 0 {
			bpffilter := strings.Join(flag.Args(), " ")
			fmt.Fprintf(os.Stderr, "Using BPF filter %q\n", bpffilter)
			if err = handle.SetBPFFilter(bpffilter); err != nil {
				log.Fatal("BPF filter error:", err)
			}
		}
	}

	ProcessPcapPackets(handle, extractDnsFromRawPacket)
}
