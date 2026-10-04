package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  go run signer.go keygen")
		fmt.Println("  go run signer.go sign <private_key.pem> <file_to_sign>")
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "keygen":
		generateKeys()
	case "sign":
		if len(os.Args) != 4 {
			fmt.Println("Usage: go run signer.go sign <private_key.pem> <file_to_sign>")
			os.Exit(1)
		}
		signFile(os.Args[2], os.Args[3])
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		os.Exit(1)
	}
}

func generateKeys() {
	fmt.Println("Generating RSA-4096 keypair...")
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Printf("Failed to generate key: %v\n", err)
		os.Exit(1)
	}

	// Export private key
	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	err = os.WriteFile("private_key.pem", privPEM, 0600)
	if err != nil {
		fmt.Printf("Failed to write private_key.pem: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[+] Wrote private_key.pem")

	// Export public key
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		fmt.Printf("Failed to marshal public key: %v\n", err)
		os.Exit(1)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	// Update signing.go directly
	targetPath := "internal/integrity/signing.go"
	content, err := os.ReadFile(targetPath)
	if err != nil {
		fmt.Printf("Warning: Could not read %s. Public key:\n%s\n", targetPath, string(pubPEM))
		return
	}

	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "var ScenarioPublicKeyPEM = ") {
			// Format the PEM block as a Go multi-line string
			formattedPem := "`" + string(pubPEM) + "`"
			lines[i] = "var ScenarioPublicKeyPEM = " + formattedPem
			break
		}
	}

	err = os.WriteFile(targetPath, []byte(strings.Join(lines, "\n")), 0644)
	if err != nil {
		fmt.Printf("Failed to update %s: %v\n", targetPath, err)
		os.Exit(1)
	}

	fmt.Printf("[+] Injected public key into %s\n", targetPath)
	fmt.Println("Done. Keep private_key.pem safe and NEVER commit it.")
}

func signFile(keyPath, targetPath string) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		fmt.Printf("Failed to read private key: %v\n", err)
		os.Exit(1)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		fmt.Println("Failed to decode PEM block from private key")
		os.Exit(1)
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("Failed to parse RSA private key: %v\n", err)
		os.Exit(1)
	}

	targetData, err := os.ReadFile(targetPath)
	if err != nil {
		fmt.Printf("Failed to read target file %s: %v\n", targetPath, err)
		os.Exit(1)
	}

	hash := sha256.Sum256(targetData)
	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
	if err != nil {
		fmt.Printf("Failed to sign: %v\n", err)
		os.Exit(1)
	}

	sigBase64 := base64.StdEncoding.EncodeToString(signature)
	outPath := targetPath + ".sig"
	err = os.WriteFile(outPath, []byte(sigBase64), 0644)
	if err != nil {
		fmt.Printf("Failed to write signature file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Signed %s -> %s\n", targetPath, outPath)
}
