package main

import (
	"github.com/astaxie/beego"
	"github.com/mspaulding06/portscan"
)

func main() {
	beego.Router("/", &portscan.MainController{})
	beego.Router("/portscan", &portscan.ScanController{})
	beego.Run()
}
