package portscan

// ScanResult is return from a port scan
type ScanResult struct {
	Address string `json:"address"`
	TS      int64  `json:"ts"`
	TCP     []int  `json:"tcp"`
	UDP     []int  `json:"udp"`
}

// DiffResult provides the difference between two scans
type DiffResult struct {
	Port  int    `json:"port"`
	State string `json:"state"`
}

// QueryResult represents the JSON data returned from the
// port scan API
type QueryResult struct {
	Current ScanResult   `json:"current"`
	Diff    []DiffResult `json:"diff"`
	History []ScanResult `json:"history"`
}
