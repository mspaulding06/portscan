package main

import (
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/validation"
	"regexp"
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
	this.Ctx.WriteString(address)
}

func main() {
	beego.Router("/", &MainController{})
	beego.Router("/portscan", &ScanController{})
	beego.Run()
}
