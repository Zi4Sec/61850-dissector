package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"

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
	if counter == 2 {
		os.Exit(1)
	}
	fmt.Println("Goose packet")
	fmt.Printf("id: %x\n", payload[0:2])
	fmt.Printf("goose length: %x\n", payload[2:4])
	fmt.Printf("resv1: %x\n", payload[4:6])
	fmt.Printf("resv2: %x\n", payload[6:8])
	fmt.Printf("resv2: %x\n", payload[6:8])
	// fmt.Printf("goose pdu length: %x\n", payload[9:10])
	fmt.Printf("goose pdu length: %x\n", payload[10:11])

	var gocbref_len int32
	err := binary.Read(bytes.NewReader(payload[12:13]), binary.BigEndian, &gocbref_len)
	if err != nil {
		fmt.Println("ERR", err)
		return
	}
	fmt.Printf("gocbref length: %d\n", gocbref_len)

	fmt.Printf("gocbref: %x\n", payload[13:(13+gocbref_len)])

}
