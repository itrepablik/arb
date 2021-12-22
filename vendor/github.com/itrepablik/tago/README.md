![Tago](https://user-images.githubusercontent.com/58651329/80477734-0cfd4c00-897f-11ea-84f6-ce4fb6c495bb.png)
Use **tago** to encrypt any classified text with secured random secret keys for the mixture to formulate the encrypted text and able to decrypt it with the same secret key when you need to extract the whole classified text back to a normal phrase.

# Installation
```
go get -u github.com/itrepablik/tago
```

# Usage
```
package main

import (
	"fmt"
	"log"

	"github.com/itrepablik/tago"
)

func main() {
	// Generate a secure random salt
	secretKey, err := tago.GenerateSecretKey(32)
	if err != nil {
		log.Fatalf("error generating secret key: %s", err)
	}

	// ************************************************************************
	// Encrypt a string
	// ************************************************************************
	plaintext := "Hello World!"
	ciphertext, iv, err := tago.Encrypt(plaintext, string(secretKey))
	if err != nil {
		log.Fatalf("error encrypting string: %s", err)
	}
	if ciphertext == plaintext {
		log.Fatalln("plaintext and ciphertext should not be the same")
	}

	fmt.Printf("plaintext: %s\nciphertext: %s\niv: %s", plaintext, ciphertext, iv)

	// ************************************************************************
	// Decrypt a ciphertext
	// ************************************************************************
	decrypted, err := tago.Decrypt(ciphertext, string(secretKey), iv)
	if err != nil {
		log.Fatalf("error decrypting string: %s", err)
	}
	if decrypted != plaintext {
		log.Fatalln("plaintext and decrypted should be the same")
	}

	fmt.Println("\ndecrypted:", decrypted)
}
```

# Subscribe to Maharlikans Code Youtube Channel:
Please consider subscribing to my Youtube Channel to recognize my work on any of my tutorial series. Thank you so much for your support!
https://www.youtube.com/c/MaharlikansCode?sub_confirmation=1

# License
Code is distributed under MIT license, feel free to use it in your proprietary projects as well.
