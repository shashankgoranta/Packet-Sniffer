package main

import (
	"flag"
	"fmt"
	"encoding/hex"
	"os"
	"regexp"
	"strconv"
	"strings"
	gopacket "github.com/google/gopacket"
	layers "github.com/google/gopacket/layers"
	pcap "github.com/google/gopacket/pcap"
)

// Execute function for read from pcap
func Execute_Read(fileI string, filterI string, bpf string) {
	//fmt.Println(fileI)
	var outputline = ""
	var srcIp = ""
	var dstIp = ""
	var srcMAC = ""
	var dstMAC = ""
	var Time = ""
	var EtherType = ""
	var Length = ""
	var protocol = ""
	var srcPort = ""
	var dstPort = ""
	var flags = " "
	var payload []byte

	//read data from pcap file
	if handle, err := pcap.OpenOffline(fileI); err != nil {
		fmt.Println("Cannot find the file mentioned")
		os.Exit(1)
	}else{
		//bpf logic
		if bpf != "none" {
			//fmt.Println("BPF "+bpf)
			if err:=handle.SetBPFFilter(bpf); err!=nil{
				fmt.Println("Invalid BPF filter")
				os.Exit(1)
			}
		}	

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			
			//resetting loop vars 
			outputline = ""
			flags = " "
			payload = nil
			srcIp = ""
			dstIp = ""
		  srcMAC = ""
			dstMAC = ""
			Time = ""
			EtherType = ""
			Length = ""
			protocol = ""
			srcPort = ""
			dstPort = ""
			flags = " "
			payload = nil

			// //fields from Metadata
			if packet.Metadata() != nil {
				Time = (packet.Metadata().Timestamp).String()
				Length = strconv.Itoa(packet.Metadata().CaptureInfo.Length)
			} else {
				Time = ""
				Length = "0"
			}

			//ethernet layer data
			if etherLayer := packet.Layer(layers.LayerTypeEthernet); etherLayer != nil {
				ether, _ := etherLayer.(*layers.Ethernet)
				srcMAC = (ether.SrcMAC).String() + "-->"
				dstMAC = (ether.DstMAC).String()
				payload = ether.Payload
			} else {
				srcMAC = ""
				dstMAC = ""
			}

			//get ethertype
			dataBytes := make([]byte, 1518)
			dataBytes = packet.LinkLayer().LayerContents()
			var str = hex.Dump(dataBytes[12:14])
			hexethertype := strings.Fields(str)
			EtherType = "0x" + hexethertype[1] + hexethertype[2]

			//IPv4 layer data
			if IPv4Layer := packet.Layer(layers.LayerTypeIPv4); IPv4Layer != nil {
				iplayer, _ := IPv4Layer.(*layers.IPv4)
				srcIp = (iplayer.SrcIP).String() 
				dstIp = (iplayer.DstIP).String()
			} else {
				srcIp = ""
				dstIp = ""
			}

			//tcp and udp layer data
			//checking if layer is present
			re := regexp.MustCompile("[0-9]+")
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				//fmt.Println("This is TCP")
				tcp, _ := tcpLayer.(*layers.TCP)
				protocol = "TCP"
				srcPort = re.FindString((tcp.SrcPort).String())
				dstPort = re.FindString((tcp.DstPort).String())

				//get tcp flags -- SYN, ACK, FIN, RST, PSH, URG, ECE, CWR, NS
				m := make(map[string]bool)
				m["SYN"] = tcp.SYN
				m["ACK"] = tcp.ACK
				m["FIN"] = tcp.FIN
				m["RST"] = tcp.RST
				m["PSH"] = tcp.PSH
				m["URG"] = tcp.URG
				m["ECE"] = tcp.ECE
				m["CWR"] = tcp.CWR
				m["NS"] = tcp.NS
				for key, element := range m {
					if element == true {
						flags = flags + " " + key
					}
				}
			}
			if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				protocol = "UDP"
				srcPort = re.FindString((udp.SrcPort).String())
				dstPort = re.FindString((udp.DstPort).String())
			}
			if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
				//icmp, _ := icmpLayer.(*layers.ICMPv4)
				protocol = "ICMP"
			}
			if protocol != "TCP" && protocol != "UDP" && protocol != "ICMP" {
				protocol = "Other"
			}

			//Checking the -s input and printing only necessary packets.. if no pattern is found then breaking the loop
			//if no input is read for -s param then go takes None
			//this is case sensitive
			if filterI != "None" {
				//fmt.Println(filterI)
				if !(strings.Contains(hex.Dump(payload), filterI)) {
					continue
				}
			}
			//formatting src and dest ipa nd ports
			srcIp = srcIp + ":" + srcPort + "-->"
			dstIp = dstIp + ":" + dstPort 
			// //append to a string each value as desired
			outputline = Time + " " + srcMAC + dstMAC + " type " + EtherType + " len " + Length + " " + srcIp +  dstIp + " " + protocol + " " + flags + "\n" + hex.Dump(payload)

			fmt.Println(outputline)

		}
	}

}

//Execute function for open live
func Execute_Live(interfaceI string, filterI string, bpf string) {
	//fmt.Println("In liveCapture")
	//fmt.Println(pcap.FindAllDevs())
	var outputline = ""
	var srcIp = ""
	var dstIp = ""
	var srcMAC = ""
	var dstMAC = ""
	var Time = ""
	var EtherType = ""
	var Length = ""
	var protocol = ""
	var srcPort = ""
	var dstPort = ""
	var flags = " "
	var payload []byte
	//for ubuntu give proper interface name here such as eth0
	if handle, err := pcap.OpenLive(interfaceI, 1600, true, pcap.BlockForever); err != nil {
		fmt.Println("The provided interface is not present. Please check")
		os.Exit(1)
	}else {
		//bpf logic
		if bpf != "none" {
			//fmt.Println("BPF "+bpf)
			if err:=handle.SetBPFFilter(bpf); err!=nil{
				fmt.Println("Invalid BPF filter")
				os.Exit(1)
			}
		}	
		
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			
			//resetting loop vars 
			outputline = ""
			flags = " "
			payload = nil
			srcIp = ""
			dstIp = ""
		  srcMAC = ""
			dstMAC = ""
			Time = ""
			EtherType = ""
			Length = ""
			protocol = ""
			srcPort = ""
			dstPort = ""
			flags = " "
			payload = nil

			// //fields from Metadata
			if packet.Metadata() != nil {
				Time = (packet.Metadata().Timestamp).String()
				Length = strconv.Itoa(packet.Metadata().CaptureInfo.Length)
			} else {
				Time = ""
				Length = "0"
			}

			// // //ethernet layer data
			if etherLayer := packet.Layer(layers.LayerTypeEthernet); etherLayer != nil {
				ether, _ := etherLayer.(*layers.Ethernet)
				srcMAC = (ether.SrcMAC).String() + "-->"
				dstMAC = (ether.DstMAC).String()
				payload = ether.Payload
			} else {
				srcMAC = ""
				dstMAC = ""
			}

			//get ethertype
			dataBytes := make([]byte, 1518)
			dataBytes = packet.LinkLayer().LayerContents()
			var str = hex.Dump(dataBytes[12:14])
			hexethertype := strings.Fields(str)
			EtherType = "0x" + hexethertype[1] + hexethertype[2]

			//IPv4 layer data
			if IPv4Layer := packet.Layer(layers.LayerTypeIPv4); IPv4Layer != nil {
				iplayer, _ := IPv4Layer.(*layers.IPv4)
				srcIp = (iplayer.SrcIP).String() 
				dstIp = (iplayer.DstIP).String()
			} else {
				srcIp = ""
				dstIp = ""
			}

			//tcp and udp layer data
			//checking if layer is present
			re := regexp.MustCompile("[0-9]+")
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				//fmt.Println("This is TCP")
				tcp, _ := tcpLayer.(*layers.TCP)
				protocol = "TCP"
				srcPort = re.FindString((tcp.SrcPort).String())
				dstPort = re.FindString((tcp.DstPort).String())

				//get tcp flags -- SYN, ACK, FIN, RST, PSH, URG, ECE, CWR, NS
				m := make(map[string]bool)
				m["SYN"] = tcp.SYN
				m["ACK"] = tcp.ACK
				m["FIN"] = tcp.FIN
				m["RST"] = tcp.RST
				m["PSH"] = tcp.PSH
				m["URG"] = tcp.URG
				m["ECE"] = tcp.ECE
				m["CWR"] = tcp.CWR
				m["NS"] = tcp.NS
				for key, element := range m {
					if element == true {
						flags = flags + " " + key
					}
				}
			}
			if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				protocol = "UDP"
				srcPort = re.FindString((udp.SrcPort).String())
				dstPort = re.FindString((udp.DstPort).String())
			}
			if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
				//icmp, _ := icmpLayer.(*layers.ICMPv4)
				protocol = "ICMP"
			}
			if protocol != "TCP" && protocol != "UDP" && protocol != "ICMP" {
				protocol = "Other"
			}
			
			//Checking the -s input and printing only necessary packets.. if no pattern is found then breaking the loop
			//if no input is read for -s param then go takes None
			//this is case sensitive
			if filterI != "None" {
				//fmt.Println(filterI)
				if !(strings.Contains(hex.Dump(payload), filterI)) {
					continue
				}
			}

			//formatting src and dest ipa nd ports
			srcIp = srcIp + ":" + srcPort + "-->"
			dstIp = dstIp + ":" + dstPort 
			// //append to a string each value as desired
			outputline = Time + " " + srcMAC + dstMAC + " type " + EtherType + " len " + Length + " " + srcIp +  dstIp + " " + protocol + " " + flags + "\n" + hex.Dump(payload)

			fmt.Println(outputline)
		}
	}
}
//main function
func main() {
	//fmt.Println("Initialised mydump.go file..")
	//get arguments from command line
	//capture -i -r -s
	var interfaceI string
	var fileI string
	var filterI string
	var bpf string
	// flags declaration using flag package
	flag.StringVar(&interfaceI, "i", "None", "Specify interface. Default is eth0")
	flag.StringVar(&fileI, "r", "None", "Include -r flag only if input is from a file")
	flag.StringVar(&filterI, "s", "None", "No string found, state your string after -s flag")
	flag.Parse()
	//fmt.Println(interfaceI)
	//fmt.Println(fileI)
	//fmt.Println(stringI)

	//getting bpf filter statement
	//if even number of args are present then the bpf filter is givesn if odd number of args are present then not
	if(len(os.Args)%2 == 0){
		bpf = os.Args[len(os.Args)-1]
	}else{
		bpf = "None" 
	}
	
	//fmt.Println("BPF filter" + bpf)
	var defdev = ""
	//switch either to file reader or live packet capture and call respective functions
	if fileI == "None" {
		//fmt.Println("This is live capture")
		if(interfaceI == "None"){
			//getting the interface
			device_list, err := pcap.FindAllDevs()
			if err != nil {
				fmt.Println("Cannot query the devs on this machine")
				os.Exit(1)
			}
			for _, device := range device_list {
				defdev = device.Name
				break
			}
		}else{
			defdev = interfaceI
		}
		//fmt.Println(defdev)
		Execute_Live(defdev, filterI, strings.ToLower(bpf))
	} else {
		//fmt.Println("This is an input from a pcap file")
		Execute_Read(fileI, filterI, strings.ToLower(bpf))
	}
}
