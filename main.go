package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"gopkg.in/yaml.v3"
)

// Config strucutre for configuration file
type Config struct {
	BlockedIPs []string `json:"blocked_ips" yaml:"blocked_ips"`
	//TODO BlockedPorts []int `json:"blocked_ports" yaml:"blocked_ports"`
}

// LoadConfig reads configuration from a file
func loadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("Failed to open config file: %w", err)
	}

	defer file.Close()

	config := &Config{}
	switch ext := getFileExtension(path); ext {
	case "yaml", "yml":
		if err := yaml.NewDecoder(file).Decode(config); err != nil {
			return nil, fmt.Errorf("Failed to parse YAML: %w", err)
		}
	case "json":
		if err := json.NewDecoder(file).Decode(config); err != nil {
			return nil, fmt.Errorf("Failed to parse JSON: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported file extension: %s", ext)
	}
	return config, nil
}

// GetFileExtension extracts the file extension from the path
func getFileExtension(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '.' {
			return path[i+1:]
		}
	}
	return ""
}

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
	// Get the configuration file from command-line arguments
	if len(os.Args) < 2 {
		log.Fatalf("usage: %s <config-file> [interface]", os.Args[0])
	}
	configPath := os.Args[1]

	// Load configuration
	config, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	fmt.Printf("Loaded configuration: %+v\n", config)

	// Load the eBPF objects from the generated code
	var objs dropObjects
	if err := loadDropObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Populate blocked IPs into the eBPF map
	for i, ip := range config.BlockedIPs {
		ipUint32, err := ipToUint32(ip)
		if err != nil {
			log.Printf("invalid IP address in config: %s", ip)
			continue
		}
		key := uint32(i)
		if err := objs.BlockedIpMap.Put(key, ipUint32); err != nil {
			log.Printf("failed to add IP to map: %v", err)
		}
	}

	// Use interface provided by user or default to eth0
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
