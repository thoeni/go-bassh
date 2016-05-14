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
