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

type ScanController struct {
	beego.Controller
}

type JSONError struct {
	Error string `json:"error"`
}

func (this *ScanController) ValidateAddress() (string, error) {
	address := this.GetString("address")
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

func (this *ScanController) Post() {
	acceptHeader := this.Ctx.Input.Header("Accept")
	if strings.Contains(acceptHeader, "application/json") {
		this.WriteJSON()
		return
	}
	this.WriteHTML()
}

func (this *ScanController) WriteJSON() {
	address, err := this.ValidateAddress()
	if err != nil {
		message := JSONError{
			err.Error(),
		}
		this.Data["json"] = &message
		this.ServeJSON()
		return
	}

	resolvedAddress := ResolveHost(address)
	if resolvedAddress == "" {
		message := JSONError{
			"Unknown address provided.",
		}
		this.Data["json"] = &message
		this.ServeJSON()
		return
	}

	current, err := PortScan(resolvedAddress)
	if err != nil {
		message := JSONError{
			err.Error(),
		}
		this.Data["json"] = &message
		this.ServeJSON()
		return
	}

	queryRes := QueryResult{}

	queryRes.Current = current
	history, err := QueryScans(resolvedAddress)
	if err != nil {
		message := JSONError{
			"Unable to retrieve query history.",
		}
		this.Data["json"] = &message
		this.ServeJSON()
	}
	queryRes.History = history
	this.Data["json"] = &queryRes
	this.ServeJSON()
}

func (this *ScanController) WriteHTML() {
	address, err := this.ValidateAddress()
	if err != nil {
		this.Ctx.WriteString(fmt.Sprintf("<p>%v</p>", err))
		return
	}
	resolvedAddress := ResolveHost(address)
	if resolvedAddress == "" {
		this.Ctx.WriteString("<p>Unknown address provided.</p>")
	} else {
		res, err := PortScan(resolvedAddress)
		if err != nil {
			this.Ctx.WriteString(err.Error())
		}
		this.Ctx.WriteString(`
		<!doctype html>
		<html>
		<head>
		<title>Port Scanner</title>
		</head>
		<body>
		`)
		this.Ctx.WriteString(`<p><a href="/">Back to Port Scanner</a></p>`)
		this.WriteScanResultHTML(res)
		history, err := QueryScans(res.Address)
		if err != nil {
			this.Ctx.WriteString("<p>Unable to retrieve history</p>")
		}
		for _, entry := range history {
			this.WriteScanResultHTML(entry)
		}
		this.Ctx.WriteString(`
		</body>
		</html>
		`)
	}
}

func (this *ScanController) WriteScanResultHTML(res ScanResult) {
	this.Ctx.WriteString(fmt.Sprintf("<p>IP Address: %v</p>", res.Address))
	this.Ctx.WriteString(fmt.Sprintf("<p>Scan Time: %v</p>", time.Unix(res.TS, 0).Local().String()))
	this.Ctx.WriteString(fmt.Sprintf("<p>TCP Open Ports: %v</p>", res.TCP))
	this.Ctx.WriteString(fmt.Sprintf("<p>UDP Open Ports: %v</p>", res.UDP))
}
