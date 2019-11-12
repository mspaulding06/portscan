package portscan

import (
	"database/sql"
	"errors"
	// Not used directly
	_ "github.com/go-sql-driver/mysql"
)

func QueryLatestScan(address string) (int64, error) {
	db, err := sql.Open("mysql", "portscan:portscan@/portscans")
	defer db.Close()
	if err != nil {
		return 0, err
	}
	rows, err := db.Query(`SELECT ts FROM portscans WHERE address = ? ORDER BY ts DESC LIMIT 1`, address)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if rows.Next() {
		var ts int64
		if err := rows.Scan(&ts); err != nil {
			return 0, nil
		}
		return ts, nil
	}
	return 0, errors.New("No previous entry")
}

func InsertScan(address string, scan ScanResult) error {
	db, err := sql.Open("mysql", "portscan:portscan@/portscans")
	defer db.Close()
	if err != nil {
		return err
	}
	for _, port := range scan.TCP {
		_, err := db.Exec(`INSERT INTO portscans (address, ts, port, proto) values (?, ?, ?, ?)`, address, scan.TS, port, "tcp")
		if err != nil {
			return err
		}
	}
	for _, port := range scan.UDP {
		_, err := db.Exec(`INSERT INTO portscans (address, ts, port, proto) values (?, ?, ?, ?)`, address, scan.TS, port, "udp")
		if err != nil {
			return err
		}
	}
	return nil
}

func QueryScans(address string) ([]ScanResult, error) {
	db, err := sql.Open("mysql", "portscan:portscan@/portscans")
	defer db.Close()
	if err != nil {
		return []ScanResult{}, err
	}
	rows, err := db.Query(`SELECT ts FROM portscans WHERE address = ?`, address)
	if err != nil {
		return []ScanResult{}, err
	}
	defer rows.Close()
	res := []ScanResult{}
	for rows.Next() {
		var ts string
		if err := rows.Scan(&ts); err != nil {
			return res, err
		}
		scanRes, err := QueryScanResult(address, ts)
		if err != nil {
			return res, err
		}
		res = append(res, scanRes)
	}
	return res, nil
}

func QueryScanResult(address string, ts string) (ScanResult, error) {
	db, err := sql.Open("mysql", "portscan:portscan@/portscans")
	defer db.Close()
	if err != nil {
		return ScanResult{}, err
	}
	rows, err := db.Query(`SELECT port, proto FROM portscans WHERE address = ? AND ts = ?`, address, ts)
	if err != nil {
		return ScanResult{}, err
	}
	defer rows.Close()
	res := ScanResult{}
	for rows.Next() {
		var port int
		var proto string
		if err := rows.Scan(&port, &proto); err != nil {
			return res, err
		}
		if proto == "tcp" {
			res.TCP = append(res.TCP, port)
		} else {
			res.UDP = append(res.UDP, port)
		}
	}
	return res, nil
}
