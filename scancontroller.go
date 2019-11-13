package portscan

import (
	"errors"
	"fmt"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/validation"
	"regexp"
	"strings"
	"time"
)

// ScanController is for the port scan API
type ScanController struct {
	beego.Controller
}

// JSONError represents an error in JSON format
type JSONError struct {
	Error string `json:"error"`
}

// Post is for posting to the scanner API
func (sc *ScanController) Post() {
	acceptHeader := sc.Ctx.Input.Header("Accept")
	if strings.Contains(acceptHeader, "application/json") {
		sc.writeJSON()
		return
	}
	sc.writeHTML()
}

func (sc *ScanController) writeJSON() {
	address, err := sc.validateAddress()
	if err != nil {
		message := JSONError{
			err.Error(),
		}
		sc.Data["json"] = &message
		sc.ServeJSON()
		return
	}

	resolvedAddress := ResolveHost(address)
	if resolvedAddress == "" {
		message := JSONError{
			"Unknown address provided.",
		}
		sc.Data["json"] = &message
		sc.ServeJSON()
		return
	}

	current, err := PortScan(resolvedAddress)
	if err != nil {
		message := JSONError{
			err.Error(),
		}
		sc.Data["json"] = &message
		sc.ServeJSON()
		return
	}

	queryRes := QueryResult{}

	queryRes.Current = current
	history, err := QueryScans(resolvedAddress)
	if err != nil {
		message := JSONError{
			"Unable to retrieve query history.",
		}
		sc.Data["json"] = &message
		sc.ServeJSON()
		return
	}
	queryRes.History = history

	prevTS, err := QueryLatestScan(current.Address)
	if err != nil {
		message := JSONError{
			"Unable to retrieve previous scan.",
		}
		sc.Data["json"] = &message
		sc.ServeJSON()
		return
	}
	previous, err := QueryScanResult(current.Address, prevTS)
	if err != nil {
		message := JSONError{
			"Unable to retrieve previous scan.",
		}
		sc.Data["json"] = &message
		sc.ServeJSON()
		return
	}
	queryRes.Diff = GenerateScanDiff(current, previous)

	sc.Data["json"] = &queryRes
	sc.ServeJSON()
}

func (sc *ScanController) writeHTML() {
	address, err := sc.validateAddress()
	if err != nil {
		sc.Ctx.WriteString(fmt.Sprintf("<p>%v</p>", err))
		return
	}
	resolvedAddress := ResolveHost(address)
	if resolvedAddress == "" {
		sc.Ctx.WriteString("<p>Unknown address provided.</p>")
	} else {
		res, err := PortScan(resolvedAddress)
		if err != nil {
			sc.Ctx.WriteString(err.Error())
		}
		sc.Ctx.WriteString(`
		<!doctype html>
		<html>
		<head>
		<title>Port Scanner</title>
		</head>
		<body>
		`)
		sc.Ctx.WriteString(`<p><a href="/">Back to Port Scanner</a></p>`)
		sc.Ctx.WriteString(fmt.Sprintf("<h2>Results for IP: %v</h2>", res.Address))
		sc.Ctx.WriteString("<h3>Current Result</h3>")
		sc.writeScanResultHTML(res)
		sc.Ctx.WriteString("<h3>Diff From Previous</h3>")
		prevTS, err := QueryLatestScan(res.Address)
		if err != nil {
			sc.Ctx.WriteString("<h3>Unable to retrieve previous scan</h3>")
		}
		previous, err := QueryScanResult(res.Address, prevTS)
		if err != nil {
			sc.Ctx.WriteString("<h3>Unable to retrieve previous scan</h3>")
		}
		diff := GenerateScanDiff(res, previous)
		sc.Ctx.WriteString("<ul>")
		for _, entry := range diff {
			sc.Ctx.WriteString(fmt.Sprintf("<li>Port %v/%v was %v</li>", entry.Port, entry.Proto, entry.State))
		}
		sc.Ctx.WriteString("</ul>")
		history, err := QueryScans(res.Address)
		if err != nil {
			sc.Ctx.WriteString("<h3>Unable to retrieve history</h3>")
		}
		sc.Ctx.WriteString("<h3>Previous Results</h3>")
		for _, entry := range history {
			sc.writeScanResultHTML(entry)
		}
		sc.Ctx.WriteString(`
		</body>
		</html>
		`)
	}
}

func (sc *ScanController) writeScanResultHTML(res ScanResult) {
	sc.Ctx.WriteString(fmt.Sprintf("<h3>%v</h3>", time.Unix(res.TS, 0).Local().String()))
	sc.Ctx.WriteString("<ul>")
	sc.Ctx.WriteString(fmt.Sprintf("<li>TCP Open Ports: %v</li>", res.TCP))
	sc.Ctx.WriteString(fmt.Sprintf("<li>UDP Open Ports: %v</li>", res.UDP))
	sc.Ctx.WriteString("</ul>")
}

func (sc *ScanController) validateAddress() (string, error) {
	address := sc.GetString("address")
	valid := validation.Validation{}
	res := valid.IP(address, "address")
	if !res.Ok {
		res = valid.Match(address, regexp.MustCompile(`^[a-zA-Z]\w*(\.[a-zA-Z]\w*)*$`), "hostname")
		if !res.Ok {
			return address, errors.New("Not a valid IP address or hostname")
		}
	}
	return address, nil
}
