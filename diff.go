package portscan

// GenerateScanDiff create a diff between two port scans
func GenerateScanDiff(current, previous ScanResult) []DiffResult {
	diff := []DiffResult{}
	for _, curPort := range current.TCP {
		if !hasPort(previous.TCP, curPort) {
			res := DiffResult{
				Port:  curPort,
				Proto: "tcp",
				State: "opened",
			}
			diff = append(diff, res)
		}
	}
	for _, prevPort := range previous.TCP {
		if !hasPort(current.TCP, prevPort) {
			res := DiffResult{
				Port:  prevPort,
				Proto: "tcp",
				State: "closed",
			}
			diff = append(diff, res)
		}
	}
	for _, curPort := range current.UDP {
		if !hasPort(previous.UDP, curPort) {
			res := DiffResult{
				Port:  curPort,
				Proto: "udp",
				State: "opened",
			}
			diff = append(diff, res)
		}
	}
	for _, prevPort := range previous.UDP {
		if !hasPort(current.UDP, prevPort) {
			res := DiffResult{
				Port:  prevPort,
				Proto: "udp",
				State: "closed",
			}
			diff = append(diff, res)
		}
	}
	return diff
}

func hasPort(ports []int, checkPort int) bool {
	for _, port := range ports {
		if checkPort == port {
			return true
		}
	}
	return false
}
