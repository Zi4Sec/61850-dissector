package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const GOOSE = 0x88B8

var counter int = 0

func main() {
	pcapFile := flag.String("f", "", "path to pcap file")
	flag.Parse()
	Capture(*pcapFile)
}

func GetPackets(InterfaceAddress string, TrafficFile string, PacketFilter string) chan gopacket.Packet {

	if InterfaceAddress != "" {
		if handle, err := pcap.OpenLive(InterfaceAddress, 1600, true, pcap.BlockForever); err != nil {
			panic(err)
		} else {
			if err := handle.SetBPFFilter(PacketFilter); err != nil {
				log.Fatal(err)
			}
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			return packetSource.Packets()
		}
	} else {
		if handle, err := pcap.OpenOffline(TrafficFile); err != nil {
			panic(err)
		} else {
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			packetSource.Lazy = false
			packetSource.NoCopy = true
			return packetSource.Packets()
		}
	}
}

func Capture(pcapFile string) {

	packets := GetPackets("", pcapFile, "")
	log.Println("Started")
	for packet := range packets {

		if packet == nil {
			return
		}

		if packet.LinkLayer() == nil {
			log.Println("Link layer is nil")
			continue
		}

		if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
			eth, _ := ethLayer.(*layers.Ethernet)
			if eth.EthernetType == GOOSE { //Check for GOOSE packet
				dissector(eth.Payload)
			}
		}
	}
}

func dissector(payload []byte) {
	counter++
	if counter == 3 {
		os.Exit(1)
	}
	index := int64(0)
	fmt.Printf("id: %d\n", binary.BigEndian.Uint16(payload[index:index+2]))
	index += 2
	fmt.Printf("goose length: %d\n", binary.BigEndian.Uint16(payload[index:index+2]))
	index += 2
	fmt.Printf("resv1: %x\n", payload[index:index+2])
	index += 2
	fmt.Printf("resv2: %x\n", payload[index:index+2])
	index += 3
	// fmt.Printf("tag?: %x\n", payload[9:10])
	fmt.Printf("goose pdu length: %d\n", ByteArrayToInt(payload[index:index+1]))
	index += 3
	gocbref_len := ByteArrayToInt(payload[index : index+1])
	fmt.Printf("gocbref length: %d\n", gocbref_len)
	fmt.Printf("gocbref: %v\n", string(payload[index:index+gocbref_len]))

	index += gocbref_len + 2
	tatl := ByteArrayToInt(payload[index : index+1])
	fmt.Printf("timeAllowedtoLive length: %d\n", tatl)
	index += 1
	fmt.Printf("timeAllowedtoLive: %x, %d\n", payload[index:index+tatl], binary.BigEndian.Uint16(payload[index:index+tatl]))
}

func ByteArrayToInt(arr []byte) int64 {
	val := int64(0)
	size := len(arr)
	for i := 0; i < size; i++ {
		*(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(&val)) + uintptr(i))) = arr[i]
	}
	return val
}
