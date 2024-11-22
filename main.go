package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
)

func ipToUint32(ip string) (uint32, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return 0, fmt.Errorf("invalid IP address: %s", ip)
	}
	ipv4 := parsedIP.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf("not an IPv4 address: %s", ip)
	}
	return binary.BigEndian.Uint32(ipv4), nil
}

func main() {
	// Load the eBPF objects from the generated code
	var objs dropObjects
	if err := loadDropObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Get the IP address to block from the command line arguments
	if len(os.Args) < 2 {
		log.Fatalf("usage: %s <blocked-ip> [interface]", os.Args[0])
	}
	blockedIP := os.Args[1]
	blockedIPUint32, err := ipToUint32(blockedIP)
	if err != nil {
		log.Fatalf("invalid IP address: %v", err)
	}

	fmt.Printf("Blocking IP: %s (0x%x)\n", blockedIP, blockedIPUint32)

	// Write the blocked IP address to the BPF map
	key := uint32(0)
	if err := objs.BlockedIpMap.Put(key, blockedIPUint32); err != nil {
		log.Fatalf("writing to BPF map: %v", err)
	}

	// Find the network interface to attach the program to
	ifaceName := "eth0"
	if len(os.Args) > 2 {
		ifaceName = os.Args[2]
	}

	// Get the network interface by name
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("getting interface %s: %v", ifaceName, err)
	}

	// Attach the XDP program to the network interface
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDropIp,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("attaching XDP program to interface %s: %v", ifaceName, err)
	}
	defer link.Close()

	fmt.Printf("Attached XDP program to interface %s\n", ifaceName)

	// Wait for a signal (e.g., Ctrl+C) to exit
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("Detaching XDP program and exiting")
}
