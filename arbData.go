package arb

import (
	"bytes"
	"encoding/gob"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/itrepablik/tago"
)

var mu = &sync.RWMutex{} // read-write mutex, multiple readers, single writer

// RawData returns the raw arbritary data
type RawData struct {
	SensitiveData string `json:"sensitive_data"`
}

// ArbData is the arbritary data model to be stored in the memory
type ArbData struct {
	ArbKey    string `json:"arb_key"`    // The encrypted arbritary data as key
	SecretKey string `json:"secret_key"` // The secret key to decrypt the arbritary data
	IV        []byte `json:"iv"`         // The initialization vector to decrypt the arbritary data
	ExpiresIn int64  `json:"expires_in"` // Unix timestamp, auto-set to 30 minutes
}

// ArbFacts is the arbritary facts model to be stored in the memory
type ArbFacts struct {
	Facts map[string][]byte
}

// AF is the arbritary facts map
var AF = ArbFacts{Facts: make(map[string][]byte)}

// RunClearExpiredArbKeys sets the 'ArbFacts' map
func RunClearExpiredArbKeys() {
	go func() {
		for {
			ClearExpiredArbKeys()
			time.Sleep(time.Second * 5)
		}
	}()
}

// ClearExpiredArbKeys removes all the expired arb keys
func ClearExpiredArbKeys() {
	mu.RLock()
	defer mu.RUnlock()

	for k, v := range AF.Facts {
		if v != nil {
			payLoad, err := DecodePayload(k)
			if err != nil {
				continue
			}
			if payLoad.ExpiresIn < time.Now().Unix() {
				AF.Remove(k)
			}
		}
	}
}

// CreateArbKey creates a new arbritary key
func CreateArbKey(arbKey string, payLoad ArbData) (string, error) {
	if len(strings.TrimSpace(arbKey)) == 0 {
		return "", errors.New("arb key is required")
	}

	encBytes, err := EncodePayload(payLoad)
	if err != nil {
		return "", err
	}

	_, isArbKeyFound := AF.Get(arbKey)
	if isArbKeyFound {
		AF.Remove(arbKey)
	}

	AF.Add(arbKey, encBytes)
	return arbKey, nil
}

// DecodeArbKey decodes the arbitrary key
func DecodeArbKey(arbKey string) (string, error) {
	if strings.TrimSpace(arbKey) == "" {
		return "", errors.New("arb key is required")
	}

	arbData, err := DecodePayload(arbKey)
	if err != nil {
		return "", err
	}

	// Decrypt the arb key
	decodedArbKey, err := tago.Decrypt(arbKey, arbData.SecretKey, arbData.IV)
	if err != nil {
		return "", err
	}
	return decodedArbKey, nil
}

// EncodePayload encodes the arbitrary payload using gob
func EncodePayload(payLoad ArbData) ([]byte, error) {
	var data bytes.Buffer
	enc := gob.NewEncoder(&data)

	err := enc.Encode(payLoad)
	if err != nil {
		return data.Bytes(), err
	}
	return data.Bytes(), nil
}

// DecodePayload extracts the arbitrary payload
func DecodePayload(arbKey string) (ArbData, error) {
	if len(strings.TrimSpace(arbKey)) == 0 {
		return ArbData{}, errors.New("arb key is required")
	}

	arbBytes, _ := AF.Get(arbKey)
	dec := gob.NewDecoder(bytes.NewReader(arbBytes))

	var payLoad = ArbData{}
	err := dec.Decode(&payLoad)
	if err != nil {
		return ArbData{}, errors.New("arb key not found: " + arbKey)
	}
	return payLoad, nil
}

// Add insert a new arbitrary into the 'ArbFacts' map
func (t *ArbFacts) Add(arbKey string, encBytes []byte) error {
	// Check if arbKey is empty
	if len(strings.TrimSpace(arbKey)) == 0 {
		return errors.New("arb key is required")
	}

	mu.RLock()
	defer mu.RUnlock()

	// Check if the arbitrary key already exists
	_, isArbKeyFound := t.Get(arbKey)
	if isArbKeyFound {
		return errors.New("arb key already exists: " + arbKey)
	}
	t.Facts[arbKey] = encBytes
	return nil
}

// Get gets the arbitrary from the 'ArbFacts' map by arb key
func (t *ArbFacts) Get(arbKey string) ([]byte, bool) {
	mu.RLock()
	defer mu.RUnlock()

	encBytes, ok := t.Facts[arbKey]
	return encBytes, ok
}

// Remove any single stored arbitrary from the 'ArbFacts' map
func (t *ArbFacts) Remove(arbKey string) (bool, error) {
	if len(strings.TrimSpace(arbKey)) == 0 {
		return false, errors.New("arb key is required")
	}

	mu.RLock()
	defer mu.RUnlock()

	_, isTokFound := t.Get(arbKey)
	if isTokFound {
		delete(t.Facts, arbKey)
		return true, nil
	}
	return false, errors.New("arb key not found: " + arbKey)
}
