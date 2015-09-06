# mcpacket
mcpacket is a command line multicast traffic sender/reciever
*	Support IPv4/IPv6
* ASM and SSM

All functions are tested under Ubuntu 14.04 64b;


# Usage
Following are the supported commands:
```
mcpacket ver1.0 - a multicast traffic sender/reciver tool
  -grp string
    	Multicast group address
  -ifname string
    	Network interface name
  -msrc string
    	Multicast source address,mode ssm only
  -plen int
    	Packet length (default 200)
  -pnum int
    	Number of packets to send (default 5)
  -port int
    	UDP port (default 5001)
  -sender
    	As multicast source sending traffic
  -sint int
    	Sending interval in seconds (default 1)
  -tos int
    	TOS/Traffic class of the packet to be sent
  -ttl int
    	TTL of the packet to be sent (default 32)

```
Examples:
* sending traffic : mcpacket -sender -grp=224.1.1.1 -ifname=eth0

* listen in ASM mode: mcpacket -grp=224.1.1.1 -ifname=eth0
* listen in SSM mode: mcpacket -grp=224.1.1.1 -ifname=eth0 -msrc 192.168.1.100


# To Build/Run Source Code
mcpakcet is written with Go 1.5, require following non-core packages:
*  golang.org/x/net/ipv4
*  golang.org/x/net/ipv6

# License
GPLv2
