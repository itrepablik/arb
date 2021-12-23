![arb package](https://user-images.githubusercontent.com/58651329/147187623-8e0ede54-8188-491c-9757-a4742907b0dc.png)

# Installation
```
go get -u github.com/itrepablik/arb
```

# Arb
Manages your arbitrary data to be securely encrypted and decrypted accordingly in your next Go's app. In most cases, you can use this when you want to encrypt your plain text password at any of your configuration files, or you wanted to encrypt your sensitive information before it submits to the online forms like login events at the client side.

Although the SSL is the frontline security protocol for our site, it's good to have a plan b type of security level just to ensure that when the SSL is not being renewed automatically, at least we have some degree of protection against the cyberattack when our vulnerable and valuable data being transmitted back and forth to our web server.

# Usage
This is how you can use the arb package to generate secure encrypted text and able to decode it securely as well.
```
package main

import (
		"fmt"
	"log"
	"time"

	"github.com/itrepablik/arb"
	"github.com/itrepablik/tago"
)

func init() {
	// Initialize the arb package to automatically removed expired arb keys stored in the memories.
	arb.RunClearExpiredArbKeys()
}

func main() {
		sensitiveData := "This is a secret message"

	// Generate a secure 32 bytes random salt
	secretKey, err := tago.GenerateSecretKey(32)
	if err != nil {
		log.Fatal(err)
	}

	ciphertext, iv, err := tago.Encrypt(sensitiveData, string(secretKey))
	if err != nil {
		log.Fatal(err)
	}

	// Create a new arb key
	arbData := arb.ArbData{
		ArbKey:    ciphertext,
		SecretKey: secretKey,
		IV:        iv,
		ExpiresIn: time.Now().Add(time.Minute * 30).Unix(),
	}

	arbKey, err := arb.CreateArbKey(ciphertext, arbData)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("arbKey:", arbKey)

	// To decode the arb key, we need to know the secret key and iv stored in the memory of the server.
	decodedArbKey, err := arb.DecodeArbKey(arbKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("decodedArbKey:", decodedArbKey)
}
```

# Subscribe to Maharlikans Code Youtube Channel:
Please consider subscribing to my Youtube Channel to recognize my work on any of my tutorial series. Thank you so much for your support!
https://www.youtube.com/c/MaharlikansCode?sub_confirmation=1

# License
Code is distributed under MIT license, feel free to use it in your proprietary projects as well.
