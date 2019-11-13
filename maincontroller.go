package portscan

import (
	"github.com/astaxie/beego"
)

type MainController struct {
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
