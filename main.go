package main

import (
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"

	"encoding/pem"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
	"strings"
	"syscall"
)

type sshCommand struct {
	Path   string
	Env    []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

type sshClient struct {
	Config *ssh.ClientConfig
	Host   string
	Port   int
}

func (client *sshClient) RunCommand(cmd *sshCommand) error {
	var (
		session *ssh.Session
		err     error
	)

	if session, err = client.newSession(); err != nil {
		return err
	}
	defer session.Close()

	if err = client.prepareCommand(session, cmd); err != nil {
		return err
	}

	err = session.Run(cmd.Path)
	return err
}

func (client *sshClient) prepareCommand(session *ssh.Session, cmd *sshCommand) error {
	for _, env := range cmd.Env {
		variable := strings.Split(env, "=")
		if len(variable) != 2 {
			continue
		}
		fmt.Println("Setting env variable ", variable[0], " to ", variable[1])
		if err := session.Setenv(variable[0], variable[1]); err != nil {
			fmt.Println("The remote system doesn't accept the setEnv command: ", err)
			return err
		}
	}

	if cmd.Stdin != nil {
		stdin, err := session.StdinPipe()
		if err != nil {
			return fmt.Errorf("Unable to setup stdin for session: %v", err)
		}
		go io.Copy(stdin, cmd.Stdin)
	}

	if cmd.Stdout != nil {
		stdout, err := session.StdoutPipe()
		if err != nil {
			return fmt.Errorf("Unable to setup stdout for session: %v", err)
		}
		go io.Copy(cmd.Stdout, stdout)
	}

	if cmd.Stderr != nil {
		stderr, err := session.StderrPipe()
		if err != nil {
			return fmt.Errorf("Unable to setup stderr for session: %v", err)
		}
		go io.Copy(cmd.Stderr, stderr)
	}

	return nil
}

func (client *sshClient) newSession() (*ssh.Session, error) {
	connection, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", client.Host, client.Port), client.Config)
	if err != nil {
		return nil, fmt.Errorf("Failed to dial: %s", err)
	}

	session, err := connection.NewSession()
	if err != nil {
		return nil, fmt.Errorf("Failed to create session: %s", err)
	}

	modes := ssh.TerminalModes{
		// ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		session.Close()
		return nil, fmt.Errorf("request for pseudo terminal failed: %s", err)
	}

	return session, nil
}

func publicKeyFile(file string) ssh.AuthMethod {
	fmt.Printf("Private key is at: %s", file)
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Println("Error while reading the file: ", err)
		return nil
	}
	decryptedBuffer := decryptIfEncrypted(buffer)
	key, err := ssh.ParsePrivateKey(decryptedBuffer)
	if err != nil {
		fmt.Println("Error while parsing private key: ", err)
		return nil
	}
	fmt.Println("Private key succesfully decripted and decoded.")
	return ssh.PublicKeys(key)
}

func decryptIfEncrypted(buffer []byte) []byte {
	//  Decode the key extracting the pem.Block structure
	block, _ := pem.Decode(buffer)
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	//  Verify if the pem.block is Ecnrypted
	if x509.IsEncryptedPEMBlock(block) {
		fmt.Println("Key is encrypted, specify decrypt passphrase: ")
		bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
		if err == nil {
			fmt.Println("\nPassword typed: " + string(bytePassword))
		}
		passphrase := string(bytePassword)
		decryptedPem, err := x509.DecryptPEMBlock(block, []byte(strings.TrimSpace(passphrase)))
		if err != nil {
			fmt.Println("Error while reading the file: ", err)
			panic("failed to decrypt certificate PEM")
		}
		//  Recreating the decoded block to be returned
		var newBlock pem.Block
		newBlock.Type = block.Type
		newBlock.Headers = block.Headers
		newBlock.Bytes = decryptedPem
		//  Encoding block into []byte and returning
		return pem.EncodeToMemory(&newBlock)
	}
	fmt.Println("Key is not encrypted.")
	return buffer
}

func sshAgent() ssh.AuthMethod {
	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		return ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers)
	}
	return nil
}

func configureCredentials() *ssh.ClientConfig {
	var config ssh.ClientConfig
	fmt.Printf("SSH username: ")
	fmt.Scanf("%s", &config.User)
	var pemKeyPath string
	fmt.Printf("SSH pem key location (absolute path): ")
	fmt.Scanf("%s", &pemKeyPath)
	config.Auth = []ssh.AuthMethod{(publicKeyFile(pemKeyPath))}
	return &config
}

func main() {
	// ssh.Password("your_password")
	sshConfig := configureCredentials()

	client := &sshClient{
		Config: sshConfig,
		Host:   "52.18.96.94",
		Port:   22,
	}

	cmd := &sshCommand{
		Path:   "/bin/bash",
		Env:    []string{""},
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}

	fmt.Printf("Running command: %s\n", cmd.Path)
	if err := client.RunCommand(cmd); err != nil {
		fmt.Fprintf(os.Stderr, "command run error: %s\n", err)
		os.Exit(1)
	}
}
