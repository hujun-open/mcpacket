/* mcpacket, a multicast traffic sender/reciver tool

*/
package main

import (
	"flag"
	"fmt"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

type MyIP interface {
	JoinSourceSpecificGroup(ifi *net.Interface, group, source net.Addr) error
	LeaveSourceSpecificGroup(ifi *net.Interface, group, source net.Addr) error
	JoinGroup(ifi *net.Interface, group net.Addr) error
	LeaveGroup(ifi *net.Interface, group net.Addr) error
	ExcludeSourceSpecificGroup(ifi *net.Interface, group, source net.Addr) error
	IncludeSourceSpecificGroup(ifi *net.Interface, group, source net.Addr) error
	Close() error
}

func IPver(addr string) string {
	if net.ParseIP(addr) == nil {
		return ""
	}
	if strings.Contains(addr, ":") {
		return "ipv6"
	} else {
		if strings.Count(addr, ".") != 3 {
			return "ipv6"
		} else {
			return "ipv4"
		}
	}
}

func IsMulticast(addr string) bool {
	ipaddr := net.ParseIP(addr)
	if ipaddr == nil {
		return false
	}
	return ipaddr.IsMulticast()
}

func ListenToThePackets(p MyIP, ipver string, gaddr *string, uport *int) {
	buf := make([]byte, 10000)
	i := 0
	var n int
	var pktsrc net.Addr
	var pktdst net.IP
	var err error
	grp_addr := net.ParseIP(*gaddr)
	for {
		if ipver == "udp6" {
			var rcm *ipv6.ControlMessage
			n, rcm, pktsrc, err = p.(*ipv6.PacketConn).ReadFrom(buf)
			pktdst = rcm.Dst

		} else {
			var rcm *ipv4.ControlMessage
			n, rcm, pktsrc, err = p.(*ipv4.PacketConn).ReadFrom(buf)
			pktdst = rcm.Dst

		}
		if err != nil {
			log.Fatalln(err)
		}
		if pktdst.IsMulticast() {
			if pktdst.Equal(grp_addr) {
				log.Printf("got packet #%d from src %s -> [%s]:%d, size %d\n", i, pktsrc.String(), *gaddr, *uport, n)
				i += 1
			} else {
				log.Printf("got a unexpected packet from src %s, size %d\n", pktsrc.String(), n)
			}
		}

	}

}

func processSignal(sigs chan os.Signal, done chan bool, p MyIP, mmode string, grp net.UDPAddr, src net.UDPAddr, oif *net.Interface) {
	<-sigs
	log.Println("Exiting")
	switch mmode {
	case "asm":
		p.LeaveGroup(oif, &grp)
	case "ssm":
		p.LeaveSourceSpecificGroup(oif, &grp, &src)
	}
	p.Close()
	done <- true
}

func main() {
	version_str := "mcpacket ver1.0 - a multicast traffic sender/reciver tool"
	fmt.Println(version_str)
	var oif *net.Interface
	var err error
	var uport = flag.Int("port", 5001, "UDP port")
	var gaddr = flag.String("grp", "", "Multicast group address")
	var msrcaddr = flag.String("msrc", "", "Multicast source address,mode ssm only")
	var sender = flag.Bool("sender", false, "As multicast source sending traffic ")
	var pktsize = flag.Int("plen", 200, "Packet length")
	var pnum = flag.Int("pnum", 5, "Number of packets to send")
	var sint = flag.Int("sint", 1, "Sending interval in seconds")
	var ttl = flag.Int("ttl", 32, "TTL of the packet to be sent")
	var tos = flag.Int("tos", 0, "TOS/Traffic class of the packet to be sent")
	switch runtime.GOOS {
	case "windows":
		var ifindex = flag.Int("ifindex", -1, "Network interface index")
		flag.Parse()
		if *ifindex == -1 {
			flag.PrintDefaults()
			log.Fatalln("Specify a valid interface index!")

		}
		oif, err = net.InterfaceByIndex(*ifindex)
		if err != nil {
			log.Fatalln(err)
		}
	default:
		var ifname = flag.String("ifname", "", "Network interface name")
		flag.Parse()
		if *ifname == "" {
			flag.PrintDefaults()
			log.Fatalln("Specify a valid interface name")

		}
		oif, err = net.InterfaceByName(*ifname)
		if err != nil {
			log.Fatalln(err)
		}
	}
	if *gaddr == "" {
		flag.PrintDefaults()
		log.Fatalln("Specify a valid multicast group address")
	}
	var ipver string
	switch IPver(*gaddr) {
	case "ipv6":
		ipver = "udp6"
	case "ipv4":
		ipver = "udp4"
	default:
		log.Fatalf("%s is not a valid IP address\n", *gaddr)
	}
	if IsMulticast(*gaddr) == false {
		log.Fatalf("%s is not a multicast address\n", *gaddr)
	}
	var mmode string
	if *msrcaddr == "" {
		mmode = "asm"
	} else {
		mmode = "ssm"
	}
	if mmode == "ssm" && IPver(*msrcaddr) == "" {
		log.Fatalf("%s is not valid IP address\n", *msrcaddr)
	}
	if mmode == "ssm" && IPver(*gaddr) != IPver(*msrcaddr) {
		log.Fatalf("%s and %s are not same address family\n", *gaddr, *msrcaddr)
	}
	if mmode == "ssm" && *msrcaddr == "" && *sender == false {
		flag.PrintDefaults()
		log.Fatalln("Specify a valid multicast source address for SSM mode")

	}

	mgroup := net.UDPAddr{IP: net.ParseIP(*gaddr), Port: *uport}
	c, err := net.ListenPacket(ipver, fmt.Sprintf(":%d", *uport))
	if err != nil {
		log.Fatalln(err)
	}
	var p MyIP
	if ipver == "udp6" {
		p = ipv6.NewPacketConn(c)
	} else {
		p = ipv4.NewPacketConn(c)
	}

	if runtime.GOOS != "windows" {
		switch ipver {
		case "udp6":
			err = p.(*ipv6.PacketConn).SetControlMessage(ipv6.FlagDst, true)
		case "udp4":
			err = p.(*ipv4.PacketConn).SetControlMessage(ipv4.FlagDst, true)
		}
		if err != nil {
			log.Fatalln(err)
			log.Fatalln("Unable to set control message")
		}
	}
	switch *sender {
	case false:
		var ssmsource net.UDPAddr
		switch mmode {
		case "ssm":
			ssmsource = net.UDPAddr{IP: net.ParseIP(*msrcaddr)}
			err := p.JoinSourceSpecificGroup(oif, &mgroup, &ssmsource)
			if err != nil {
				fmt.Println(err)
				log.Fatalf("unable to join channel (S,G): (%s,%s)\n", *msrcaddr, *gaddr)
			}
			fmt.Printf("As a SSM listener, joined channel (S,G): (%s,%s)\n", *msrcaddr, *gaddr)
		case "asm":
			if err := p.JoinGroup(oif, &mgroup); err != nil {
				log.Println(err)
				log.Fatalf("unable to join channel (*,G): (*,%s)\n", *gaddr)
			}
			defer p.LeaveGroup(oif, &mgroup)
			fmt.Printf("As a ASM listener, joined channel (*,G): (*,%s)\n", *gaddr)
		default:
			log.Fatalf("Only SSM and ASM mode are supported currently")
		}
		go ListenToThePackets(p, ipver, gaddr, uport)
		sigs := make(chan os.Signal, 1)
		done := make(chan bool, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		processSignal(sigs, done, p, mmode, mgroup, ssmsource, oif)
		<-done

	case true:
		fmt.Printf("As sender, packets (size %dB) sending to [%s]:%d:\n", *pktsize, *gaddr, *uport)
		pkt := make([]byte, *pktsize)
		var err error
		switch ipver {
		case "udp6":
			err = p.(*ipv6.PacketConn).SetMulticastHopLimit(*ttl)
			if err != nil {
				fmt.Println(err)
				log.Fatalln("failed to set TTL\n")
			}
			if runtime.GOOS != "windows" {
				err = p.(*ipv6.PacketConn).SetTrafficClass(*tos)
				if err != nil {
					fmt.Println(err)
					log.Fatalln("failed to set traffic class\n")
				}
			}
			err = p.(*ipv6.PacketConn).SetMulticastInterface(oif)
			if err != nil {
				fmt.Println(err)
				log.Fatalln("failed to set multicast interface\n")
			}
		case "udp4":
			err = p.(*ipv4.PacketConn).SetMulticastTTL((*ttl))
			if err != nil {
				fmt.Println(err)
				log.Fatalln("failed to set TTL\n")
			}
			err = p.(*ipv4.PacketConn).SetTOS(*tos)
			if err != nil {
				fmt.Println(err)
				log.Fatalln("failed to set TOS\n")
			}
			err = p.(*ipv4.PacketConn).SetMulticastInterface(oif)
			if err != nil {
				fmt.Println(err)
				log.Fatalln("failed to set multicast interface\n")
			}

		}

		for i := 1; i <= *pnum; i += 1 {
			switch ipver {
			case "udp6":
				_, err = p.(*ipv6.PacketConn).WriteTo(pkt, nil, &mgroup)
			case "udp4":
				_, err = p.(*ipv4.PacketConn).WriteTo(pkt, nil, &mgroup)

			}

			if err != nil {
				log.Fatalln(err)
			} else {
				log.Printf("packet #%d sent to [%s]:%d\n", i, *gaddr, *uport)
			}
			if i < *pnum {
				time.Sleep(time.Duration(*sint*1000) * time.Millisecond)
			}
		}

	}
}
