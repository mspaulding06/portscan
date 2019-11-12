package main

import (
	"fmt"
	"github.com/mspaulding06/portscan"
	"os"
)

func main() {
	fmt.Println("Starting Port Scanning Service")
	ipAddress := portscan.ResolveHost(os.Args[1])
	fmt.Printf("Scanning IP %s\n", ipAddress)
	res, err := portscan.PortScan(ipAddress)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(res)
	if err := portscan.InsertScan(ipAddress, res); err != nil {
		fmt.Println(err)
	}
}
