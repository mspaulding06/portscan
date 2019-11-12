package portscan

type ScanResult struct {
	Address string `json:"address"`
	TS      int64  `json:"ts"`
	TCP     []int  `json:"tcp"`
	UDP     []int  `json:"udp"`
}

type DiffResult struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	State   string `json:"state"`
}

type QueryResult struct {
	Current ScanResult   `json:"current"`
	Diff    []DiffResult `json:"diff"`
	History []ScanResult `json:"history"`
}
