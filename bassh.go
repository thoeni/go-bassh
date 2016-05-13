package bassh

import (
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"

	"encoding/pem"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

//SSHParams contains params to setup the Session
type SSHParams struct {
	Env    []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

//SSHClient wraps the ssh client configuration and the host/port information
type SSHClient struct {
	Session *ssh.Session
	Config  *ssh.ClientConfig
	Host    string
	Port    int
}

//InitSession returns a session initialised with the given params
func (client *SSHClient) InitSession(params *SSHParams) error {
	var (
		session *ssh.Session
		err     error
	)

	if session, err = client.newSession(); err != nil {
		return err
	}

	if err = client.prepareCommand(session, params); err != nil {
		return err
	}

	client.Session = session

	return nil
}

func (client *SSHClient) prepareCommand(session *ssh.Session, params *SSHParams) error {
	for _, env := range params.Env {
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

	if params.Stdin != nil {
		stdin, err := session.StdinPipe()
		if err != nil {
			return fmt.Errorf("Unable to setup stdin for session: %v", err)
		}
		go io.Copy(stdin, params.Stdin)
	}

	if params.Stdout != nil {
		stdout, err := session.StdoutPipe()
		if err != nil {
			return fmt.Errorf("Unable to setup stdout for session: %v", err)
		}
		go io.Copy(params.Stdout, stdout)
	}

	if params.Stderr != nil {
		stderr, err := session.StderrPipe()
		if err != nil {
			return fmt.Errorf("Unable to setup stderr for session: %v", err)
		}
		go io.Copy(params.Stderr, stderr)
	}

	return nil
}

func (client *SSHClient) newSession() (*ssh.Session, error) {
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

func decodeKeyForAuthMethod(file string) ssh.AuthMethod {
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

func configureCredentialsInteractive() *ssh.ClientConfig {
	var config ssh.ClientConfig
	fmt.Printf("SSH username: ")
	fmt.Scanf("%s", &config.User)
	var pemKeyCommand string
	fmt.Printf("SSH pem key location (absolute path): ")
	fmt.Scanf("%s", &pemKeyCommand)
	config.Auth = []ssh.AuthMethod{(decodeKeyForAuthMethod(pemKeyCommand))}
	return &config
}

//ConfigureCredentials returns the ClientConfig struct to be used as part of the
//SSHClient definition
func ConfigureCredentials(username string, keypath string) *ssh.ClientConfig {
	var config ssh.ClientConfig
	config.User = username
	pemKeyCommand := keypath
	config.Auth = []ssh.AuthMethod{(decodeKeyForAuthMethod(pemKeyCommand))}
	return &config
}

func createClientInteractive(sshConfig *ssh.ClientConfig) *SSHClient {
	fmt.Printf("IP address: ")
	var ipAddr string
	var port int
	fmt.Scanf("%s", &ipAddr)
	fmt.Printf("SSH port: ")
	fmt.Scanf("%d", &port)

	return CreateClient(sshConfig, ipAddr, port)
}

//CreateClient takes a *ssh.ClientConfig struct as input, ipAddress of the target
//machine and the ssh port, and returns an *SSHClient where a command can be Run on
func CreateClient(sshConfig *ssh.ClientConfig, ipAddr string, port int) *SSHClient {
	return &SSHClient{
		Config: sshConfig,
		Host:   ipAddr,
		Port:   port,
	}
}

//Run opens an SSH session and Runs the command passed as an argument
func (client *SSHClient) Run(command string) {
	defer client.Session.Close()
	if err := client.Session.Run(command); err != nil {
		fmt.Fprintf(os.Stderr, "command run error: %s\n", err)
		if client.Session == nil {
			fmt.Println("Session not initialised.")
		}
		os.Exit(1)
	}
	return
}

//RunBash runs /bin/bash on the client
func (client *SSHClient) RunBash() {
	params := &SSHParams{
		Env:    []string{""},
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}

	if err := client.InitSession(params); err == nil {
		client.Run("/bin/bash")
	}
}

//RunBashInteractive allows the user to configure the SSH client interactively and
//executes /bin/bash on the remote host specified interactively by the user
func RunBashInteractive() {
	params := &SSHParams{
		Env:    []string{""},
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}

	sshConfig := configureCredentialsInteractive()
	client := createClientInteractive(sshConfig)

	if err := client.InitSession(params); err == nil {
		client.Run("/bin/bash")
	}
}
