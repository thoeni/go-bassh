#go-bassh [![Go Report Card](https://goreportcard.com/badge/github.com/thoeni/go-bassh)](https://goreportcard.com/report/github.com/thoeni/go-bassh)  [![Build Status](https://travis-ci.org/thoeni/go-bassh.svg?branch=master)](https://travis-ci.org/thoeni/go-bassh)   [![Coverage Status](http://coveralls.io/repos/github/thoeni/go-bassh/badge.svg?branch=master)](https://coveralls.io/github/thoeni/go-bassh?branch=master)

`go-bassh` library can be used to quickly open a tty on a remote server, given username, .pem key (at the moment only key without passphrase, but soon the passphrase will be supported), the ip address of the machine, and the SSH port

###Usage example

```go
package main

import (
	"github.com/thoeni/go-bassh"
)

func main() {
	sshConfig, _ := bassh.ConfigureCredentials("ubuntu", "/Users/johndoe/.ssh/myprivatekey.pem")
	client := bassh.CreateClient(sshConfig, "123.234.123.234", 22)
	client.RunBash()
}
```
