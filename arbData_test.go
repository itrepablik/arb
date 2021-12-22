package arb

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/itrepablik/tago"
)

func TestClearExpiredArbKeys(t *testing.T) {
	// Clear the expired arb keys
	go func() {
		for {
			ClearExpiredArbKeys()
			time.Sleep(time.Second * 5)
		}
	}()
}

func TestCreateArbKey(t *testing.T) {
	arbKey, err := setTestData()
	if err != nil {
		t.Errorf("error: %s", err)
		return
	}
	t.Logf("arbKey: %s", arbKey)

	// Test to decode the arb key
	decodedArbKey, err := DecodePayload(arbKey)
	if err != nil {
		t.Errorf("error: %s", err)
		return
	}
	t.Logf("decodedArbKey: %v", decodedArbKey)
}

func TestDecodeArbKey(t *testing.T) {
	arbKey, err := setTestData()
	if err != nil {
		t.Errorf("error: %s", err)
		return
	}

	decodedArbKey, err := DecodeArbKey(arbKey)
	if err != nil {
		t.Errorf("error: %s", err)
		return
	}
	t.Logf("decodedArbKey: %s", decodedArbKey)
}

func setTestData() (string, error) {
	// Get the sample sensitive data in JSON format from the file
	data, err := unmarshalJSONdata("sensitiveData")
	if err != nil {
		return "", err
	}

	// Encrypt the sensitive data
	ciphertext, secretKey, iv, err := encryptArbData(data.SensitiveData)
	if err != nil {
		return "", err
	}

	// Create a new arb key
	arbData := ArbData{
		ArbKey:    ciphertext,
		SecretKey: secretKey,
		IV:        iv,
		ExpiresIn: time.Now().Add(time.Second * 10).Unix(),
	}

	arbKey, err := CreateArbKey(ciphertext, arbData)
	if err != nil {
		return "", err
	}
	return arbKey, nil
}

func encryptArbData(sensitiveData string) (string, string, []byte, error) {
	// Generate a secure 32 bytes random salt
	secretKey, err := tago.GenerateSecretKey(32)
	if err != nil {
		return "", "", nil, err
	}

	ciphertext, iv, err := tago.Encrypt(sensitiveData, string(secretKey))
	if err != nil {
		return "", "", nil, err
	}
	return ciphertext, secretKey, iv, nil
}

func unmarshalJSONdata(fn string) (RawData, error) {
	var data RawData
	fileName := fmt.Sprintf("./testData/%s.json", fn)
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		return data, err
	}

	err = json.Unmarshal(file, &data)
	if err != nil {
		return data, err
	}
	return data, nil
}
