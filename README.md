#go-bassh [![Go Report Card](https://goreportcard.com/badge/github.com/thoeni/go-bassh)](https://goreportcard.com/report/github.com/thoeni/go-bassh)  [![Build Status](https://travis-ci.org/thoeni/go-bassh.svg?branch=master)](https://travis-ci.org/thoeni/go-bassh)   [![Coverage Status](https://coveralls.io/repos/github/thoeni/go-bassh/badge.svg?branch=master)](https://coveralls.io/github/thoeni/go-bassh?branch=master)

`go-bassh` library can be used to quickly open a tty on a remote server, given username, .pem key (at the moment only key without passphrase, but soon the passphrase will be supported), the ip address of the machine, and the SSH port

####DISCLAIMER
This small library is a prototype and I'm working on it while learning Go, therefore it's not intended to be used in any production environment whatsoever.
Test coverage is low because I'm still learning how to write tests in Go, and it will take some time before achieving an acceptable level of coverage.
Feel free to fork, make it better, and raise a pull request if you want to contribute.

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
