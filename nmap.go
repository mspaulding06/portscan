package portscan

import (
	"bytes"
	"errors"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// PortScan is where the magic happens
// Actually calls nmap and parses output
func PortScan(ipAddress string) (ScanResult, error) {
	cmd := exec.Command("nmap", "--open", ipAddress)
	epoch := time.Now().Unix()
	out, err := cmd.Output()
	if err != nil {
		return ScanResult{}, err
	}
	res, err := parseScanResult(out)
	res.TS = epoch
	return res, err
}

func parseScanResult(out []byte) (ScanResult, error) {
	res := ScanResult{}
	lines := bytes.Split(out, []byte("\n"))
	for _, line := range lines {
		re := regexp.MustCompile(`^\d+/(tcp|udp)`)
		match := re.Find(line)
		if len(match) > 0 {
			portRes := strings.Split(string(match), "/")
			port, err := strconv.Atoi(portRes[0])
			if err != nil {
				return res, err
			}
			if portRes[1] == "tcp" {
				res.TCP = append(res.TCP, port)
			} else {
				res.UDP = append(res.UDP, port)
			}
		} else {
			line := string(line)
			if strings.HasPrefix(line, "Nmap done") {
				hostRe := regexp.MustCompile(`\((\d+) host(s|) up\)`)
				matches := hostRe.FindStringSubmatch(line)
				hosts, err := strconv.Atoi(matches[1])
				if err != nil {
					return res, err
				}
				if hosts == 0 {
					return res, errors.New("No host found")
				}
				return res, nil
			}
		}
	}
	// Should never get here
	return res, errors.New("Error parsing port scan output")
}
