package portscan

import (
	"github.com/astaxie/beego"
)

// MainController is the controller for the main page
type MainController struct {
	beego.Controller
}

// Get returns main page for port scanner
func (mc *MainController) Get() {
	mc.Ctx.WriteString(`
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
