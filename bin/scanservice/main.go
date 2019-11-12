package main

import (
	"fmt"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/validation"
	"github.com/mspaulding06/portscan"
	"regexp"
	"time"
)

type MainController struct {
	beego.Controller
}

type ScanController struct {
	beego.Controller
}

func (this *MainController) Get() {
	this.Ctx.WriteString(`
	<!doctype html>
	<html>
	<head>
	  <title>Port Scanner</title>
	  <script>
	  </script>
	</head>
	<body>
	<form action="/portscan" method="post">
	<p>IP or Hostname for Port Scan</p>
	<p><input type="text" name="address" autofocus></p>
	<button type="submit">Scan Ports</button>
	</form>
	</body>
	</html>
	`)
}

func (this *ScanController) Post() {
	address := this.GetString("address")
	valid := validation.Validation{}
	res := valid.IP(address, "address")
	if !res.Ok {
		res = valid.Match(address, regexp.MustCompile(`^[a-zA-Z]\w*(\.[a-zA-Z]\w*)*$`), "hostname")
		if !res.Ok {
			this.Ctx.WriteString("<p>Not a valid IP address or hostname</p>")
		}
	}
	resolvedAddress := portscan.ResolveHost(address)
	if resolvedAddress == "" {
		this.Ctx.WriteString("<p>Unknown address provided.</p>")
	} else {
		res, err := portscan.PortScan(resolvedAddress)
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
		this.WriteScanResult(res)
		history, err := portscan.QueryScans(res.Address)
		if err != nil {
			this.Ctx.WriteString("<p>Unable to retrieve history</p>")
		}
		for _, entry := range history {
			this.WriteScanResult(entry)
		}
		this.Ctx.WriteString(`
		</body>
		</html>
		`)
	}
}

func (this *ScanController) WriteScanResult(res portscan.ScanResult) {
	this.Ctx.WriteString(fmt.Sprintf("<p>IP Address: %v</p>", res.Address))
	this.Ctx.WriteString(fmt.Sprintf("<p>Scan Time: %v</p>", time.Unix(res.TS, 0).Local().String()))
	this.Ctx.WriteString(fmt.Sprintf("<p>TCP Open Ports: %v</p>", res.TCP))
	this.Ctx.WriteString(fmt.Sprintf("<p>UDP Open Ports: %v</p>", res.UDP))
}

func main() {
	beego.Router("/", &MainController{})
	beego.Router("/portscan", &ScanController{})
	beego.Run()
}
