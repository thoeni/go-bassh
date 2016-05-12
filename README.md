#go-bassh

`go-bassh` library can be used to quickly open a tty on a remote server, given username, .pem key (at the moment only key without passphrase, but soon the passphrase will be supported), the ip address of the machine, and the SSH port

###Usage example

```
package main

import (
	"github.com/thoeni/go-bassh"
)

func main() {
	sshConfig := bassh.ConfigureCredentials("ubuntu", "/Users/johndoe/.ssh/myprivatekey.pem")
	client := bassh.CreateClient(sshConfig, "123.234.123.234", 22)
	bassh.RunSSH(client)
}
```