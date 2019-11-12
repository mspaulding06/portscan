# Really Simple Port Scanner

This is an extremely simple port scanning app.

It provides both a cli interface and also a very basic
web interface for scanning ports on servers.  The underlying
implementation uses `nmap` to accomplish this.  This
code is probably _extremely_ fragile and makes a lot of assumptions.

You've been warned!

# Installation

## Requirements
These are prerequisites used in development of the app.  It's likely
to work elsewhere, but that hasn't been tested.

* Ubuntu Bionic 18.04 LTS
* Go 1.13.4 (binaries from the website)
* MySQL Server

## Installation Instructions
1. Install MySQL Server: `sudo apt install default-mysql-server`
1. Install Go Binaries: unpack to /opt/go and set GOROOT accordingly, adding /opt/go/bin to your path
1. Set your GOPATH to somwhere you want dependencies installed
1. From the root of this repository run `go mod download`
1. Run `go build ./...` to build binaries
