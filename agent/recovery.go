package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"audspect/agent/protocol"
)

// recoveryProofDigest is the value signed to prove possession of the expired certificate's key. It binds the
// proof to this agent, to the moment, and to the exact CSR submitted. The server computes the same value (a
// golden vector test pins both sides).
func recoveryProofDigest(agentID, signedAt, csrPEM string) [32]byte {
	csrSum := sha256.Sum256([]byte(csrPEM))
	return sha256.Sum256([]byte("BAS-RECOVER-V1\n" + agentID + "\n" + signedAt + "\n" + hex.EncodeToString(csrSum[:])))
}

// attemptRecovery asks the enrolment listener for a replacement of a certificate that expired recently, proving
// it is the same agent with the expired certificate and its private key. It carries no shared secret and no
// token. The server decides whether the certificate is within its 24-hour grace period; a refusal here only
// means the caller should fall back to a fresh authorized enrolment.
func attemptRecovery(ctx context.Context, client *http.Client, enrollURL, agentID, csrPEM string) (protocol.CSRResponse, error) {
	_, _, certPath, keyPath := certPaths()
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return protocol.CSRResponse{}, fmt.Errorf("read the expired certificate: %w", err)
	}
	oldKey, err := readKeyFile(keyPath)
	if err != nil {
		return protocol.CSRResponse{}, fmt.Errorf("read the agent key: %w", err)
	}
	signedAt := time.Now().UTC().Format(time.RFC3339)
	digest := recoveryProofDigest(agentID, signedAt, csrPEM)
	sig, err := ecdsa.SignASN1(rand.Reader, oldKey, digest[:])
	if err != nil {
		return protocol.CSRResponse{}, fmt.Errorf("sign the recovery proof: %w", err)
	}
	return protocol.SubmitRecovery(ctx, client, enrollURL, protocol.RecoverRequest{
		AgentID: agentID, CSRPEM: csrPEM, ExpiredCertPEM: string(certPEM),
		SignedAt: signedAt, Proof: base64.StdEncoding.EncodeToString(sig),
	})
}

// describeRecoveryFailure says, for the log, whether the server refused or could not be reached.
func describeRecoveryFailure(err error) string {
	var se *protocol.StatusError
	if errors.As(err, &se) {
		switch se.Code {
		case http.StatusNotFound:
			return "this server does not offer certificate recovery"
		case http.StatusForbidden, http.StatusConflict, http.StatusUnauthorized:
			return fmt.Sprintf("the server refused recovery (HTTP %d: expired more than 24 hours ago, revoked, or already used)", se.Code)
		}
		return fmt.Sprintf("the server answered HTTP %d", se.Code)
	}
	return "could not reach the server: " + err.Error()
}

func logRecoveryFailure(err error) {
	log.Printf("[!] certificate recovery not possible: %s; falling back to a fresh authorized enrolment", describeRecoveryFailure(err))
}
