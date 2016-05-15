package bassh

import (
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestConfigureCredentials_credentialsAreSet(t *testing.T) {
	//Given
	expected := new(ssh.ClientConfig)
	expected.User = "testUser"

	//When
	actual, err := ConfigureCredentials("testUser", "./test-data/valid-key.pem")

	//Then
	if err != nil {
		t.Error("ConfigureCredential raised an error with a given correct input")
	}
	if actual.User != expected.User {
		t.Error("User hasn't been set into the ssh.ClientConfig")
	}
	if actual.Auth[0] == nil {
		t.Error("Auth hasn't been set into the ssh.ClientConfig")
	}
}

func TestConfigureCredentials_pemKeyDoesntExist(t *testing.T) {
	//Given
	expectedError := "Error while reading the .pem file from disk!"

	//When
	_, err := ConfigureCredentials("testUser", "./test-data/notexisting.pem")

	//Then
	if err == nil {
		t.Error("An error should have been thrown because key doesn't exist.")
	}

	if err.Error() != expectedError {
		t.Errorf("\nExpected error was: %s\nActual error was: %s", expectedError, err.Error())
	}
}

func TestConfigureCredentials_pemKeyExistsButIsInvalid(t *testing.T) {
	//Given
	expectedError := "Failed to decode certificate buffer"

	//When
	_, err := ConfigureCredentials("testUser", "./test-data/invalid-key.pem")

	//Then
	if err == nil {
		t.Fatal("An error should have been thrown because key is invalid.")
	}

	if err.Error() != expectedError {
		t.Errorf("\nExpected error was: %s\nActual error was: %s", expectedError, err.Error())
	}
}

func TestCreateClient(t *testing.T) {
	//Given
	expectedCredentials, _ := ConfigureCredentials("testUser", "./test-data/valid-key.pem")
	expectedIP := "123.123.123.123"
	expectedPort := 22

	//When
	actualSSHClient := CreateClient(expectedCredentials, expectedIP, expectedPort)

	//Then
	if expectedCredentials != actualSSHClient.Config {
		t.Error("Expected credentials don't match actual credentials")
	}

	if expectedIP != actualSSHClient.Host {
		t.Error("Expected IP donest't match actual Host IP")
	}

	if expectedPort != actualSSHClient.Port {
		t.Error("Expected port doesn't match actual port")
	}
}
