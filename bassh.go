package bassh

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
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

//InitStandardSession returns a session initialised with default params
//using stdIn, stdOut and stdErr to prepare the command
func (client *SSHClient) InitStandardSession() error {
	params := &SSHParams{
		Env:    []string{""},
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}

	return client.InitSession(params)
}

//CloseSession closes the session for the client
func (client *SSHClient) CloseSession() {
	if client.Session == nil {
		return
	}
	if err := client.Session.Close(); err != nil {
		fmt.Printf("Error while closing session: %s", err)
	}
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

func decodeKeyForAuthMethod(file string) (ssh.AuthMethod, error) {
	fmt.Printf("Private key is at: %s\n", file)
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Println("Error while reading the file: ", err)
		return nil, errors.New("Error while reading the .pem file from disk!")
	}
	decryptedBuffer, err := decryptIfEncrypted(buffer)
	if err != nil {
		return nil, err
	}
	key, err := ssh.ParsePrivateKey(decryptedBuffer)
	if err != nil {
		fmt.Println("Error while parsing private key: ", err)
		return nil, err
	}
	fmt.Println("Private key succesfully decripted and decoded.")

	return ssh.PublicKeys(key), nil
}

func decryptIfEncrypted(buffer []byte) ([]byte, error) {
	//  Decode the key extracting the pem.Block structure
	block, _ := pem.Decode(buffer)
	if block == nil {
		return nil, errors.New("Failed to decode certificate buffer")
	}
	//  Verify if the pem.block is Encrypted
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
			return nil, err
		}
		//  Recreating the decoded block to be returned
		var newBlock pem.Block
		newBlock.Type = block.Type
		newBlock.Headers = block.Headers
		newBlock.Bytes = decryptedPem
		//  Encoding block into []byte and returning
		return pem.EncodeToMemory(&newBlock), nil
	}
	fmt.Println("Key is not encrypted.")

	return buffer, nil
}

//func sshAgent() ssh.AuthMethod {
//	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
//		return ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers)
//	}
//	return nil
//}

//ConfigureCredentials returns the ClientConfig struct to be used as part of the
//SSHClient definition
func ConfigureCredentials(username string, keypath string) (*ssh.ClientConfig, error) {
	var config ssh.ClientConfig
	config.User = username
	pemKeyCommand := keypath
	authMethod, err := decodeKeyForAuthMethod(pemKeyCommand)
	if err != nil {
		return nil, err
	}
	config.Auth = []ssh.AuthMethod{authMethod}
	config.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	return &config, nil
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

	if err := client.InitStandardSession(); err != nil {
		fmt.Printf("Error while initialising SSH session! Error was: %s\n", err)
		return
	}
	defer client.CloseSession()

	if err := client.Session.Run(command); err != nil {
		fmt.Fprintf(os.Stderr, "command run error: %s\n", err)
		if client.Session == nil {
			fmt.Println("Session not initialised.")
		}
		os.Exit(1)
	}
}

//RunBash runs /bin/bash on the client
func (client *SSHClient) RunBash() {
	client.Run("/bin/bash")
}
